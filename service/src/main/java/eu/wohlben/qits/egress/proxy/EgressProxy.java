package eu.wohlben.qits.egress.proxy;

import eu.wohlben.qits.egress.grants.GrantIndex;
import eu.wohlben.qits.egress.grants.GrantRoute;
import eu.wohlben.qits.egress.identity.CallerIdentity;
import eu.wohlben.qits.egress.identity.PlatformBearers;
import io.quarkus.runtime.ShutdownDelayInitiatedEvent;
import io.quarkus.runtime.ShutdownEvent;
import io.quarkus.runtime.StartupEvent;
import io.vertx.core.Future;
import io.vertx.core.MultiMap;
import io.vertx.core.Vertx;
import io.vertx.core.http.HttpClient;
import io.vertx.core.http.HttpClientOptions;
import io.vertx.core.http.HttpClientRequest;
import io.vertx.core.http.HttpHeaders;
import io.vertx.core.http.HttpMethod;
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
import java.time.Duration;
import java.util.List;
import java.util.Locale;
import java.util.concurrent.TimeUnit;
import java.util.regex.Pattern;
import org.eclipse.microprofile.config.inject.ConfigProperty;
import org.jboss.logging.Logger;

/**
 * <b>The proxy listener</b>: a Vert.x {@link HttpServer} of its own on {@code qits.egress.proxy.port}
 * (8081), started on {@link StartupEvent} from the Quarkus-managed {@link Vertx}, reached only on the
 * wire alias {@code ${QITS_ENVIRONMENT}-qits-egress:8081}. It serves the GATEWAY form, {@code
 * /<route>/<rest>?<query>}, streams and WebSockets, scrubs secret routes' answers and drains on
 * shutdown (qits-2621), takes absolute-form requests and {@code CONNECT} from {@code HTTPS_PROXY}
 * clients ({@link Form}, qits-2622), and serves platform routes with the caller's bearer exchanged
 * at qits-idp (qits-2623).
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
 *   <li><b>The route can be served</b> — a route whose target or injection the index could not
 *       compile is 502; a secret this process does not hold is 502 {@code {"error":"secret not
 *       configured"}}, reason {@code no-secret}; a {@code platform:} route needs the caller's
 *       bearer exchanged at qits-idp ({@link PlatformBearers}), 502 {@code {"error":"token
 *       exchange refused"}} when idp refuses, reason {@code exchange-refused}.
 *   <li><b>Out</b> — through {@code vertx-http-proxy} ({@link HttpProxy#reverseProxy}), so bodies
 *       stream both ways unbuffered, to {@code <target><rest>?<query>} over TLS, with {@link
 *       EgressOutbound}, {@link ResponseScrub}, {@link EdgeHopByHop}, {@link EdgeRequestFraming}
 *       and {@link UpstreamRetry} in the chain; a WebSocket upgrade through {@link
 *       WebSocketSplice}, with the same headers out.
 * </ol>
 *
 * <p><b>Two pools</b> ({@link UpstreamPools}): a long-lived stream — a WebSocket upgrade, or a GET
 * or HEAD asking for {@code text/event-stream} ({@link #isStream}) — is proxied through a client of
 * its own, so streams to one third party can never fill the pool its ordinary calls need.
 *
 * <p>Every request writes exactly one {@link AuditLine}, when its exchange is over ({@link
 * InFlight}): its response ended, its connection closed, or — a spliced WebSocket — its socket
 * closed, the line then saying {@code method=GET status=101 reason=websocket}.
 *
 * <p><b>WebSocket upgrades never use the proxy's own upgrade path</b>: it skips the interceptor
 * chain, which would forward the caller's credentials and inject nothing. It is switched off
 * ({@link ProxyOptions#setSupportWebSocket}); {@link WebSocketSplice} handshakes and splices
 * itself.
 *
 * <p><b>Shutdown</b>: the {@code quarkus.shutdown.delay} (10 s) passes with the listener serving as
 * usual while swarm takes the task out of the VIP; then {@link #draining} refuses new connections
 * and waits for every call in flight — streams and sockets too, none closed early — up to {@code
 * quarkus.shutdown.timeout} (5 m); then {@link ShutdownLinger} holds the process 10 s more.
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

  @Inject PlatformBearers platformBearers;

  @ConfigProperty(name = "qits.egress.proxy.port", defaultValue = "8081")
  int port;

  @ConfigProperty(name = "qits.egress.proxy.host", defaultValue = "0.0.0.0")
  String host;

  @ConfigProperty(name = "quarkus.shutdown.timeout", defaultValue = "5m")
  Duration shutdownTimeout;

  private HttpServer server;

  /**
   * One proxy client and its {@link UpstreamPools}: the client every call is asked of, and {@code
   * fresh}, the same options with keep-alive off, where {@link UpstreamRetry}'s second attempt
   * dials.
   */
  record Pool(HttpClient client, HttpClient fresh, UpstreamPools pools) {}

  private Pool ordinary;

  private Pool stream;

  private WebSocketSplice webSockets;

  private ConnectTunnel tunnels;

  private final InFlight inFlight = new InFlight();

  private long checkTimer = -1;

  void start(@Observes StartupEvent ignored) throws Exception {
    ordinary = pool(UpstreamPools.ORDINARY);
    stream = pool(UpstreamPools.STREAM);
    webSockets = new WebSocketSplice(stream.client(), stream.pools());
    tunnels = new ConnectTunnel(vertx);
    checkTimer =
        vertx.setPeriodic(
            UpstreamPools.CHECK_INTERVAL_MS,
            id -> {
              ordinary.pools().check();
              stream.pools().check();
            });
    server =
        vertx
            .createHttpServer(
                new HttpServerOptions()
                    .setHost(host)
                    .setPort(port)
                    // HTTP/1.1 only: an HTTP_PROXY client, a CONNECT and a WebSocket handshake are
                    // HTTP/1.1 things, and an h2c upgrade would turn a bodyless GET into a
                    // body-less-but-unframed upstream write (Vert.x refuses it).
                    .setHttp2ClearTextEnabled(false))
            .connectionHandler(inFlight::accept)
            .requestHandler(this::handle)
            .listen()
            .toCompletionStage()
            .toCompletableFuture()
            .get(30, TimeUnit.SECONDS);
    LOG.infof("the egress proxy listens on %s:%d", host, server.actualPort());
  }

  private Pool pool(String name) {
    HttpClientOptions options = ProxyClients.proxyClientOptions(5_000);
    UpstreamPools pools = new UpstreamPools(name, options.getMaxPoolSize());
    return new Pool(
        ProxyClients.proxyClient(vertx, options, pools::connected),
        ProxyClients.proxyClient(
            vertx, ProxyClients.proxyClientOptions(5_000).setKeepAlive(false), pools::connected),
        pools);
  }

  /**
   * The shutdown delay has begun: swarm is taking this task out of the VIP and readiness answers
   * DOWN. The listener keeps serving through the delay — a caller that still reaches this task is
   * answered, not refused — and only says how much it carries.
   *
   * <p>Why this event and not {@code ShutdownEvent}: Quarkus fires this one in its {@code
   * preShutdown} pass, at the START of the delay; {@code ShutdownEvent} comes after the delay and
   * after Quarkus' own HTTP drain (8080), which is where {@link #draining} belongs.
   */
  void delayed(@Observes ShutdownDelayInitiatedEvent event) {
    LOG.infof(
        "shutting down: the proxy listener serves on through the shutdown delay, %d call(s) in"
            + " flight",
        inFlight.count());
  }

  /**
   * <b>The drain</b>, after the shutdown delay: new connections are refused and every call in
   * flight is served to its end, up to {@code quarkus.shutdown.timeout}. Then {@link
   * ShutdownLinger}, at the last priority of the same event, holds the process 10 s more. Vert.x
   * closes after every observer, so the listener and its sockets live through both.
   */
  void draining(@Observes ShutdownEvent event) {
    if (checkTimer >= 0) {
      vertx.cancelTimer(checkTimer);
    }
    if (server != null) {
      drain(shutdownTimeout);
    }
  }

  /**
   * Refuse new connections and wait for every call in flight to end, up to {@code timeout}.
   * Blocking.
   *
   * @return whether everything ended in time
   */
  boolean drain(Duration timeout) {
    return inFlight.drain(timeout);
  }

  /** Serve again after {@link #drain}: for the suites only, which keep using the listener. */
  void reopen() {
    inFlight.reopen();
  }

  /** How many calls are in flight, spliced sockets included. */
  int inFlight() {
    return inFlight.count();
  }

  /** The proxy clients' counts: ordinary first, then streams. */
  List<UpstreamPools> pools() {
    return List.of(ordinary.pools(), stream.pools());
  }

  /** The port the listener is bound to — the configured one, or the one picked for port 0. */
  public int port() {
    return server.actualPort();
  }

  /** The three request forms the listener takes. */
  enum Form {
    /** {@code /<route>/<rest>}, the caller from {@code Authorization}. */
    GATEWAY,
    /** {@code GET http(s)://host/path} from an {@code HTTP(S)_PROXY} client. */
    ABSOLUTE,
    /** {@code CONNECT host:port} from an {@code HTTPS_PROXY} client. */
    CONNECT;

    static Form of(HttpServerRequest request) {
      if (request.method() == HttpMethod.CONNECT) {
        return CONNECT;
      }
      return AbsoluteTarget.isAbsolute(request.uri()) ? ABSOLUTE : GATEWAY;
    }
  }

  void handle(HttpServerRequest request) {
    // Held until there is somewhere to send it: identifying the caller may ask idp.
    request.pause();
    Form form = Form.of(request);
    AbsoluteTarget absolute = form == Form.ABSOLUTE ? AbsoluteTarget.parse(request.uri()) : null;
    AuditLine audit =
        new AuditLine(
            request.method().name(),
            switch (form) {
              case GATEWAY -> request.path();
              case ABSOLUTE -> absolute == null ? "-" : absolute.path();
              case CONNECT -> "-";
            });
    HttpServerResponse response = request.response();
    InFlight.Exchange exchange =
        inFlight.open(request, () -> audit.write(response.getStatusCode()));
    if (exchange == null) {
      // The drain is over: the connection is closed unanswered, and the caller retries elsewhere.
      return;
    }
    Gateway gateway = form == Form.GATEWAY ? Gateway.parse(request.path()) : null;
    if (gateway != null) {
      audit.route(gateway.route());
    }
    String credential =
        form == Form.GATEWAY
            ? request.getHeader(HttpHeaders.AUTHORIZATION)
            : ProxyCredential.bearer(request.getHeader(HttpHeaders.PROXY_AUTHORIZATION));
    callers
        .identify(credential)
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
                int status = verdict.status();
                if (status == 401 && form == Form.GATEWAY) {
                  response.putHeader("WWW-Authenticate", "Bearer realm=\"qits-egress\"");
                } else if (status == 401) {
                  // A proxy client answers a 407 with its proxy credential; a 401 would be read as
                  // the target's own.
                  status = 407;
                  response.putHeader(
                      HttpHeaders.PROXY_AUTHENTICATE, "Basic realm=\"qits-egress\"");
                }
                refuse(request, audit, status, verdict.reason(), error(verdict.message()));
                return;
              }
              audit.principal(verdict.principal());
              Call call = new Call(request, audit, exchange, verdict, rawBearer(credential));
              switch (form) {
                case GATEWAY -> route(call, gateway);
                case ABSOLUTE -> absolute(call, absolute);
                case CONNECT -> connect(call);
              }
            });
  }

  /**
   * One identified call on its way: the request, its audit line and exchange, who the caller is and
   * the bearer it presented (a platform route exchanges it; nothing else reads it).
   */
  record Call(
      HttpServerRequest request,
      AuditLine audit,
      InFlight.Exchange exchange,
      CallerIdentity.Verdict verdict,
      String bearer) {}

  /** The token of a {@code Bearer …} value. */
  static String rawBearer(String authorization) {
    return authorization == null || authorization.length() < 7
        ? null
        : authorization.substring(7).trim();
  }

  private void route(Call call, Gateway gateway) {
    HttpServerRequest request = call.request();
    AuditLine audit = call.audit();
    CallerIdentity.Verdict verdict = call.verdict();
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
          noGrant(verdict, gateway.route(), method));
      return;
    }
    serve(call, route, upstreamPath(route.basePath(), gateway.rest()), request.query());
  }

  /**
   * An absolute-form request: the caller's granted route whose target origin is the request's and
   * whose base path prefixes its path — the longest such base path — or 403.
   */
  private void absolute(Call call, AbsoluteTarget target) {
    HttpServerRequest request = call.request();
    AuditLine audit = call.audit();
    CallerIdentity.Verdict verdict = call.verdict();
    if (target == null) {
      refuse(request, audit, 400, "bad-target", error("the request target is not an http(s) URL"));
      return;
    }
    audit.target(target.host(), target.path());
    GrantIndex.Table table = grants.current();
    if (table == null) {
      refuse(request, audit, 503, "no-table", error("no grant table yet"));
      return;
    }
    if (!Gateway.safe(target.path())) {
      refuse(request, audit, 400, "bad-path", error("a path with dot segments is refused"));
      return;
    }
    String method = request.method().name();
    GrantRoute route =
        target.match(table.routes(verdict.principal().application()));
    if (route == null || !route.methods().contains(method)) {
      if (route != null) {
        audit.route(route.name());
      }
      refuse(
          request,
          audit,
          403,
          route == null ? "no-grant" : "method-not-granted",
          noGrant(verdict, route == null ? null : route.name(), method)
              .put("target", target.origin()));
      return;
    }
    audit.route(route.name());
    serve(call, route, target.path(), target.query());
  }

  /**
   * {@code CONNECT host:port}: a tunnel, for a route whose target is that host and port and whose
   * {@code methods} hold {@code CONNECT}. Nothing is injected — the bytes are the caller's TLS —
   * and nothing is scrubbed; the audit line is {@code method=CONNECT path=-}, written when the
   * tunnel closes.
   */
  private void connect(Call call) {
    HttpServerRequest request = call.request();
    AuditLine audit = call.audit();
    CallerIdentity.Verdict verdict = call.verdict();
    ConnectTunnel.Authority authority = ConnectTunnel.Authority.parse(request.uri());
    if (authority == null) {
      refuse(request, audit, 400, "bad-target", error("CONNECT takes host:port"));
      return;
    }
    audit.target(authority.host(), "-");
    GrantIndex.Table table = grants.current();
    if (table == null) {
      refuse(request, audit, 503, "no-table", error("no grant table yet"));
      return;
    }
    GrantRoute reached = null;
    GrantRoute granted = null;
    // By name, so which route a refusal names does not depend on a map's order.
    List<GrantRoute> candidates =
        table.routes(verdict.principal().application()).stream()
            .sorted(java.util.Comparator.comparing(GrantRoute::name))
            .toList();
    for (GrantRoute route : candidates) {
      if (!authority.reaches(route)) {
        continue;
      }
      if (reached == null) {
        reached = route;
      }
      if (route.methods().contains("CONNECT")) {
        granted = route;
        break;
      }
    }
    if (granted == null) {
      if (reached != null) {
        audit.route(reached.name());
      }
      refuse(
          request,
          audit,
          403,
          reached == null ? "no-grant" : "method-not-granted",
          noGrant(verdict, reached == null ? null : reached.name(), "CONNECT")
              .put("target", authority.toString()));
      return;
    }
    audit.route(granted.name());
    audit.allow();
    tunnels.open(request, authority, call.exchange(), audit);
  }

  /** The 403 body: who asked for what. */
  private static JsonObject noGrant(CallerIdentity.Verdict verdict, String route, String method) {
    return new JsonObject()
        .put("error", "no grant")
        .put("principal", verdict.principal().toString())
        .put("route", route)
        .put("method", method);
  }

  /**
   * A granted route, its path decided: the route kind's own refusals, then out.
   *
   * @param path the upstream path, without the query
   * @param query the raw query, or null
   */
  private void serve(Call call, GrantRoute route, String path, String query) {
    HttpServerRequest request = call.request();
    AuditLine audit = call.audit();
    if (route.problem() != null) {
      refuse(request, audit, 502, "bad-route", error("the route cannot be served: " + route.problem()));
      return;
    }
    audit.target(route.host(), path);
    String uri = query == null || query.isEmpty() ? path : path + "?" + query;
    if (route.isPlatform()) {
      platform(call, route, uri);
      return;
    }
    String secret = secrets.value(route.secret()).orElse(null);
    if (secret == null) {
      refuse(request, audit, 502, "no-secret", error("secret not configured"));
      return;
    }
    audit.allow();
    forward(request, audit, call.exchange(), route, uri, secret);
  }

  /**
   * A platform route: the caller's bearer exchanged at qits-idp ({@link PlatformBearers}), then out
   * with that bearer and nothing to inject or scrub. idp's refusal is 502 {@code {"error":"token
   * exchange refused"}}, reason {@code exchange-refused}; an unreachable idp 503.
   */
  private void platform(Call call, GrantRoute route, String uri) {
    HttpServerRequest request = call.request();
    AuditLine audit = call.audit();
    if (call.bearer() == null || call.bearer().isEmpty()) {
      refuse(request, audit, 502, "exchange-refused", error("token exchange refused"));
      return;
    }
    platformBearers
        .bearerFor(call.bearer())
        .onComplete(
            result -> {
              PlatformBearers.Verdict verdict = result.succeeded() ? result.result() : null;
              if (verdict == null || !verdict.exchanged()) {
                int status = verdict == null ? 503 : verdict.status();
                refuse(
                    request,
                    audit,
                    status,
                    verdict == null ? "idp-unreachable" : verdict.reason(),
                    error(
                        status == 502
                            ? "token exchange refused"
                            : "the identity provider cannot be reached"));
                return;
              }
              audit.allow();
              forwardPlatform(request, audit, call.exchange(), route, uri, verdict.bearer());
            });
  }

  /** A platform call on: like {@link #forward}, with the exchanged bearer and no scrubbing. */
  private void forwardPlatform(
      HttpServerRequest request,
      AuditLine audit,
      InFlight.Exchange exchange,
      GrantRoute route,
      String uri,
      String bearer) {
    if (isWebSocketUpgrade(request)) {
      audit.reason("websocket");
      MultiMap outbound = handshakeHeaders(request.headers());
      PlatformOutbound.authorize(outbound, route, bearer);
      webSockets.handle(request, originOptions(route), uri, outbound, null, exchange, audit);
      return;
    }
    Pool pool = isStream(request) ? stream : ordinary;
    HttpProxy.reverseProxy(new ProxyOptions().setSupportWebSocket(false), pool.client())
        .origin(origin(route, pool, pool.client()))
        .addInterceptor(new PlatformOutbound(route, uri, bearer, audit))
        .addInterceptor(new EdgeHopByHop())
        .addInterceptor(new EdgeRequestFraming())
        .addInterceptor(new UpstreamRetry(route.authority(), origin(route, pool, pool.fresh())))
        .handle(request);
  }

  /**
   * Send one granted call on: a WebSocket upgrade spliced, anything else proxied through the pool
   * its kind belongs to, the answer scrubbed of the route's secret.
   */
  private void forward(
      HttpServerRequest request,
      AuditLine audit,
      InFlight.Exchange exchange,
      GrantRoute route,
      String uri,
      String secret) {
    Scrubber scrubber = Scrubber.of(secret);
    if (isWebSocketUpgrade(request)) {
      audit.reason("websocket");
      MultiMap outbound = handshakeHeaders(request.headers());
      EgressOutbound.inject(outbound, route, secret);
      webSockets.handle(
          request, originOptions(route), uri, outbound, scrubber, exchange, audit);
      return;
    }
    Pool pool = isStream(request) ? stream : ordinary;
    HttpProxy.reverseProxy(new ProxyOptions().setSupportWebSocket(false), pool.client())
        .origin(origin(route, pool, pool.client()))
        .addInterceptor(new EgressOutbound(route, uri, secret, audit))
        .addInterceptor(new ResponseScrub(scrubber, audit))
        .addInterceptor(new EdgeHopByHop())
        .addInterceptor(new EdgeRequestFraming())
        .addInterceptor(new UpstreamRetry(route.authority(), origin(route, pool, pool.fresh())))
        .handle(request);
  }

  /** Where one route's connections are asked for: its host and port, TLS for {@code https}. */
  static RequestOptions originOptions(GrantRoute route) {
    return new RequestOptions()
        .setHost(route.host())
        .setPort(route.dialPort())
        .setSsl(route.ssl())
        // The whole acquisition, a wait for a pool slot included.
        .setConnectTimeout(ProxyClients.ACQUIRE_TIMEOUT_MS);
  }

  /**
   * Where one route's connections come from, with the pool's bookkeeping: the lease is read off the
   * inbound request before the connection is asked for, and the wait is timed to the grant or the
   * failure.
   */
  private static OriginRequestProvider origin(GrantRoute route, Pool pool, HttpClient client) {
    UpstreamOrigin dialled = new UpstreamOrigin(route.host(), route.dialPort());
    return context -> {
      UpstreamLease lease = UpstreamLease.of(context.request().proxiedRequest());
      long since = pool.pools().acquiring();
      Future<HttpClientRequest> request = client.request(originOptions(route));
      return request
          .onSuccess(granted -> pool.pools().granted(dialled, since, granted, lease, false))
          .onFailure(
              failure -> {
                pool.pools().failed(dialled, since);
                LOG.warnf(
                    "no upstream connection to %s from the %s pool: %s",
                    route.authority(), pool.pools().pool(), failure.toString());
              });
    };
  }

  /**
   * The headers a WebSocket handshake carries upstream: the caller's, minus its credentials, its
   * platform headers, {@code Host} and the hop-by-hop set — all but {@code Upgrade}, which IS the
   * handshake. The injection is the caller's to add.
   */
  static MultiMap handshakeHeaders(MultiMap inbound) {
    MultiMap outbound = MultiMap.caseInsensitiveMultiMap().addAll(inbound);
    String upgrade = outbound.get(HttpHeaders.UPGRADE);
    EgressOutbound.strip(outbound);
    EdgeHopByHop.strip(outbound);
    if (upgrade != null) {
      outbound.set(HttpHeaders.UPGRADE, upgrade);
    }
    return outbound;
  }

  /**
   * Whether this exchange is a long-lived stream, and so goes through the stream pool: a WebSocket
   * upgrade, or a GET or HEAD that asks for {@code text/event-stream} ({@link #streams}).
   */
  static boolean isStream(HttpServerRequest request) {
    return isWebSocketUpgrade(request)
        || streams(request.method(), request.headers().getAll(HttpHeaders.ACCEPT));
  }

  /**
   * The SSE half of {@link #isStream}, pure. The method is half of the rule: an MCP client POSTs
   * every message with {@code Accept: application/json, text/event-stream}, and those are ordinary
   * exchanges that may stream a short answer; the long-lived thing is the GET.
   */
  static boolean streams(HttpMethod method, List<String> accepts) {
    if (method != HttpMethod.GET && method != HttpMethod.HEAD) {
      return false;
    }
    for (String accept : accepts) {
      if (accept != null && accept.toLowerCase(Locale.ROOT).contains("text/event-stream")) {
        return true;
      }
    }
    return false;
  }

  /** A GET with {@code Upgrade: websocket} and a {@code Connection} naming {@code upgrade}. */
  static boolean isWebSocketUpgrade(HttpServerRequest request) {
    if (request.method() != HttpMethod.GET) {
      return false;
    }
    String upgrade = request.getHeader(HttpHeaders.UPGRADE);
    String connection = request.getHeader(HttpHeaders.CONNECTION);
    return upgrade != null
        && upgrade.equalsIgnoreCase("websocket")
        && connection != null
        && connection.toLowerCase(Locale.ROOT).contains("upgrade");
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
