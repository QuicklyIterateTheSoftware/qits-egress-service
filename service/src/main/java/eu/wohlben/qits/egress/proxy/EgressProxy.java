package eu.wohlben.qits.egress.proxy;

import eu.wohlben.qits.egress.grants.GrantIndex;
import eu.wohlben.qits.egress.grants.GrantRoute;
import eu.wohlben.qits.egress.identity.CallerIdentity;
import io.quarkus.runtime.ShutdownEvent;
import io.quarkus.runtime.StartupEvent;
import io.vertx.core.Future;
import io.vertx.core.Vertx;
import io.vertx.core.http.HttpClient;
import io.vertx.core.http.HttpClientRequest;
import io.vertx.core.http.HttpHeaders;
import io.vertx.core.http.HttpServer;
import io.vertx.core.http.HttpServerOptions;
import io.vertx.core.http.HttpServerRequest;
import io.vertx.core.http.HttpServerResponse;
import io.vertx.core.http.RequestOptions;
import io.vertx.core.json.JsonObject;
import io.vertx.httpproxy.HttpProxy;
import io.vertx.httpproxy.OriginRequestProvider;
import io.vertx.httpproxy.ProxyOptions;
import jakarta.enterprise.context.ApplicationScoped;
import jakarta.enterprise.event.Observes;
import jakarta.inject.Inject;
import java.util.concurrent.TimeUnit;
import java.util.regex.Pattern;
import org.eclipse.microprofile.config.inject.ConfigProperty;
import org.jboss.logging.Logger;

/**
 * <b>The proxy listener</b>: a Vert.x {@link HttpServer} of its own on {@code qits.egress.proxy.port}
 * (8081), started on {@link StartupEvent} from the Quarkus-managed {@link Vertx}, reached only on the
 * wire alias {@code ${QITS_ENVIRONMENT}-qits-egress:8081}. This task serves the GATEWAY form, {@code
 * /<route>/<rest>?<query>}; absolute-form and {@code CONNECT} (qits-2622) and streams, websockets,
 * scrubbing and drain (qits-2621) join it later.
 *
 * <p>One call, in order:
 *
 * <ol>
 *   <li><b>Who</b> — {@link CallerIdentity} on {@code Authorization: Bearer}: 401 JSON when there is
 *       no credential or it is not good, 503 when the idp cannot be reached.
 *   <li><b>A table</b> — with none held, 503 {@code {"error":"no grant table yet"}}, reason {@code
 *       no-table}.
 *   <li><b>The grant</b> — the route {@code (caller application, <route>)} must exist and its
 *       {@code methods} hold the request's method: otherwise 403 {@code {"error":"no grant",
 *       "principal","route","method"}}. Only an {@code application:} principal holds routes.
 *   <li><b>The route can be served</b> — a {@code platform:} target is 501 until qits-2623; a route
 *       whose target or injection the index could not compile is 502; a secret this process does
 *       not hold is 502 {@code {"error":"secret not configured"}}, reason {@code no-secret}.
 *   <li><b>Out</b> — through {@code vertx-http-proxy} ({@link HttpProxy#reverseProxy}), so bodies
 *       stream both ways unbuffered, to {@code <target><rest>?<query>} over TLS, with {@link
 *       EgressOutbound}, {@link EdgeHopByHop}, {@link EdgeRequestFraming} and {@link UpstreamRetry}
 *       in the chain.
 * </ol>
 *
 * <p>Every request writes exactly one {@link AuditLine}, when its response ends or its connection
 * closes.
 *
 * <p><b>WebSocket upgrades are not proxied yet</b>: the proxy's own upgrade path skips the
 * interceptor chain, which would forward the caller's credentials and inject nothing. It is switched
 * off ({@link ProxyOptions#setSupportWebSocket}), so an upgrade request travels as the plain request
 * it also is, without its hop-by-hop {@code Upgrade}; qits-2621 adds the splice.
 */
@ApplicationScoped
public class EgressProxy {

  private static final Logger LOG = Logger.getLogger(EgressProxy.class);

  /** A route name: the first path segment, as the declaration allows it. */
  static final Pattern ROUTE = Pattern.compile("[a-z][a-z0-9-]{0,62}");

  @Inject Vertx vertx;

  @Inject CallerIdentity callers;

  @Inject GrantIndex grants;

  @Inject SecretStore secrets;

  @ConfigProperty(name = "qits.egress.proxy.port", defaultValue = "8081")
  int port;

  @ConfigProperty(name = "qits.egress.proxy.host", defaultValue = "0.0.0.0")
  String host;

  private HttpServer server;

  private HttpClient client;

  private HttpClient fresh;

  void start(@Observes StartupEvent ignored) throws Exception {
    client =
        ProxyClients.proxyClient(
            vertx, ProxyClients.proxyClientOptions(5_000), EgressProxy::keepAlive);
    fresh =
        ProxyClients.proxyClient(
            vertx, ProxyClients.proxyClientOptions(5_000).setKeepAlive(false), EgressProxy::keepAlive);
    server =
        vertx
            .createHttpServer(new HttpServerOptions().setHost(host).setPort(port))
            .requestHandler(this::handle)
            .listen()
            .toCompletionStage()
            .toCompletableFuture()
            .get(30, TimeUnit.SECONDS);
    LOG.infof("the egress proxy listens on %s:%d", host, server.actualPort());
  }

  void stop(@Observes ShutdownEvent ignored) throws Exception {
    // A plain stop for now: qits-2621 adds the drain that waits for calls in flight.
    if (server != null) {
      server.close().toCompletionStage().toCompletableFuture().get(10, TimeUnit.SECONDS);
    }
  }

  /** The port the listener is bound to — the configured one, or the one picked for port 0. */
  public int port() {
    return server.actualPort();
  }

  private static void keepAlive(io.vertx.core.http.HttpConnection connection) {
    UpstreamKeepAlive.apply(connection);
  }

  void handle(HttpServerRequest request) {
    // Held until there is somewhere to send it: identifying the caller may ask idp.
    request.pause();
    AuditLine audit = new AuditLine(request.method().name(), request.path());
    HttpServerResponse response = request.response();
    response.endHandler(v -> audit.write(response.getStatusCode()));
    response.closeHandler(v -> audit.write(response.getStatusCode()));
    Gateway gateway = Gateway.parse(request.path());
    if (gateway != null) {
      audit.route(gateway.route());
    }
    callers
        .identify(request.getHeader(HttpHeaders.AUTHORIZATION))
        .onComplete(
            result -> {
              if (result.failed()) {
                // identify() recovers every failure itself; this is a defect, answered safely.
                LOG.errorf(result.cause(), "identifying a caller failed");
                refuse(request, audit, 503, "idp-unreachable", error("the identity provider cannot be reached"));
                return;
              }
              CallerIdentity.Verdict verdict = result.result();
              if (!verdict.admitted()) {
                if (verdict.status() == 401) {
                  response.putHeader("WWW-Authenticate", "Bearer realm=\"qits-egress\"");
                }
                refuse(request, audit, verdict.status(), verdict.reason(), error(verdict.message()));
                return;
              }
              audit.principal(verdict.principal());
              route(request, audit, verdict, gateway);
            });
  }

  private void route(
      HttpServerRequest request,
      AuditLine audit,
      CallerIdentity.Verdict verdict,
      Gateway gateway) {
    GrantIndex.Table table = grants.current();
    if (table == null) {
      refuse(request, audit, 503, "no-table", error("no grant table yet"));
      return;
    }
    if (gateway == null) {
      refuse(
          request,
          audit,
          404,
          "no-route",
          error("no route: the gateway form is /<route>/<path>"));
      return;
    }
    if (!Gateway.safe(gateway.rest())) {
      refuse(request, audit, 400, "bad-path", error("a path with dot segments is refused"));
      return;
    }
    String method = request.method().name();
    GrantRoute route = table.route(verdict.principal().application(), gateway.route());
    if (route == null || !route.methods().contains(method)) {
      refuse(
          request,
          audit,
          403,
          route == null ? "no-grant" : "method-not-granted",
          new JsonObject()
              .put("error", "no grant")
              .put("principal", verdict.principal().toString())
              .put("route", gateway.route())
              .put("method", method));
      return;
    }
    if (route.isPlatform()) {
      audit.target("platform:" + route.platform(), request.path());
      refuse(request, audit, 501, "platform-route", error("platform routes not yet supported"));
      return;
    }
    if (route.problem() != null) {
      refuse(request, audit, 502, "bad-route", error("the route cannot be served: " + route.problem()));
      return;
    }
    String path = upstreamPath(route.basePath(), gateway.rest());
    audit.target(route.host(), path);
    String secret = secrets.value(route.secret()).orElse(null);
    if (secret == null) {
      refuse(request, audit, 502, "no-secret", error("secret not configured"));
      return;
    }
    String query = request.query();
    String uri = query == null || query.isEmpty() ? path : path + "?" + query;
    audit.allow();
    HttpProxy.reverseProxy(new ProxyOptions().setSupportWebSocket(false), client)
        .origin(origin(route, client))
        .addInterceptor(new EgressOutbound(route, uri, secret, audit))
        .addInterceptor(new EdgeHopByHop())
        .addInterceptor(new EdgeRequestFraming())
        .addInterceptor(new UpstreamRetry(route.authority(), origin(route, fresh)))
        .handle(request);
  }

  /** Where one route's connections come from: its host and port, TLS for {@code https}. */
  private static OriginRequestProvider origin(GrantRoute route, HttpClient client) {
    return context -> {
      Future<HttpClientRequest> request =
          client.request(
              new RequestOptions()
                  .setHost(route.host())
                  .setPort(route.dialPort())
                  .setSsl(route.ssl())
                  // The whole acquisition, a wait for a pool slot included.
                  .setConnectTimeout(ProxyClients.ACQUIRE_TIMEOUT_MS));
      return request.onFailure(
          failure ->
              LOG.warnf("no upstream connection to %s: %s", route.authority(), failure.toString()));
    };
  }

  /** The upstream path: the target's base path and the rest, never empty. */
  static String upstreamPath(String basePath, String rest) {
    String path = basePath + rest;
    return path.isEmpty() ? "/" : path;
  }

  private static JsonObject error(String message) {
    return new JsonObject().put("error", message);
  }

  /** Answer the gateway's own refusal: JSON, the audit line DENY. */
  private static void refuse(
      HttpServerRequest request, AuditLine audit, int status, String reason, JsonObject body) {
    audit.deny(reason);
    HttpServerResponse response = request.response();
    if (response.ended() || response.closed()) {
      return;
    }
    // Whatever body the caller is still sending is discarded rather than left in the socket.
    request.resume();
    response
        .setStatusCode(status)
        .putHeader(HttpHeaders.CONTENT_TYPE, "application/json")
        .end(body.encode());
  }

  /**
   * The gateway form's two parts.
   *
   * @param route the first path segment
   * @param rest everything after it, raw, starting with {@code /}, or empty
   */
  record Gateway(String route, String rest) {

    /** Split a raw request path, or null when its first segment is not a route name. */
    static Gateway parse(String path) {
      if (path == null || !path.startsWith("/")) {
        return null;
      }
      int slash = path.indexOf('/', 1);
      String route = slash < 0 ? path.substring(1) : path.substring(1, slash);
      if (!ROUTE.matcher(route).matches()) {
        return null;
      }
      return new Gateway(route, slash < 0 ? "" : path.substring(slash));
    }

    /**
     * Whether a rest path stays below the route's base path: no {@code .} or {@code ..} segment,
     * spelt plainly or percent-encoded, which an upstream would resolve against the base.
     */
    static boolean safe(String rest) {
      for (String segment : rest.split("/", -1)) {
        String decoded = segment.replace("%2e", ".").replace("%2E", ".");
        if (decoded.equals(".") || decoded.equals("..")) {
          return false;
        }
      }
      return true;
    }
  }
}
