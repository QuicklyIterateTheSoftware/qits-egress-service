package eu.wohlben.qits.egress.proxy;

import eu.wohlben.qits.egress.claude.ClaudeCredentials;
import eu.wohlben.qits.egress.grants.GrantIndex;
import eu.wohlben.qits.egress.grants.GrantRoute;
import eu.wohlben.qits.egress.identity.CallerIdentity;
import eu.wohlben.qits.egress.identity.PlatformBearers;
import eu.wohlben.qits.egress.tls.Leaf;
import eu.wohlben.qits.egress.tls.LeafCertificates;
import io.quarkus.runtime.ShutdownDelayInitiatedEvent;
import io.quarkus.runtime.ShutdownEvent;
import io.quarkus.runtime.StartupEvent;
import io.vertx.core.Context;
import io.vertx.core.Future;
import io.vertx.core.MultiMap;
import io.vertx.core.buffer.Buffer;
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
import io.vertx.core.net.PemTrustOptions;
import io.vertx.httpproxy.HttpProxy;
import io.vertx.httpproxy.OriginRequestProvider;
import io.vertx.httpproxy.ProxyOptions;
import jakarta.enterprise.context.ApplicationScoped;
import jakarta.enterprise.event.Observes;
import jakarta.inject.Inject;
import java.time.Duration;
import java.util.Collection;
import java.util.List;
import java.util.Locale;
import java.util.Optional;
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
 * clients ({@link Form}, qits-2622), serves platform routes with the caller's bearer exchanged at
 * qits-idp (qits-2623), and ends the TLS of a granted {@code CONNECT} on a loopback listener of its
 * own, serving every request inside the tunnel like an absolute-form one ({@link Interception},
 * qits-2644). A connection spliced from a {@code GET /egress/api/forward} websocket ({@link
 * ForwardDoor}, qits-2654) carries its caller with it ({@link ForwardedCallers}); a principal with a
 * project reaches outside hosts no route covers through the {@link Passthrough}, and the Claude
 * hosts with the login this service holds ({@link ClaudeHosts}, qits-2664): granted routes first,
 * then the Claude hosts, then the passthrough.
 *
 * <p>One call, in order:
 *
 * <ol>
 *   <li><b>Who</b> — {@link CallerIdentity} on {@code Authorization: Bearer} (the proxy forms: on
 *       {@code Proxy-Authorization}): 401 JSON when there is no credential or it is not good, 503
 *       when the idp cannot be reached. On a forward's connection a request WITHOUT that header is
 *       the forward's caller; one with it is whoever the header says.
 *   <li><b>A table</b> — with none held, 503 {@code {"error":"no grant table yet"}}, reason {@code
 *       no-table}.
 *   <li><b>The grant</b> — the route {@code (caller principal, <route>)} must exist and its
 *       {@code methods} hold the request's method: otherwise 403 {@code {"error":"no grant",
 *       "principal","route","method"}}. The caller's own principal is asked first, then, for an
 *       {@code agent:} principal, {@code project:<its project>} ({@link GrantIndex.Table#holders}):
 *       an agent holds its project's routes. The passthrough is only for what no route matches.
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

  @Inject LeafCertificates leaves;

  @Inject Passthrough passthrough;

  @Inject ClaudeHosts claude;

  @Inject ClaudeCredentials claudeCredentials;

  @ConfigProperty(name = "qits.egress.proxy.port", defaultValue = "8081")
  int port;

  @ConfigProperty(name = "qits.egress.proxy.host", defaultValue = "0.0.0.0")
  String host;

  @ConfigProperty(name = "quarkus.shutdown.timeout", defaultValue = "5m")
  Duration shutdownTimeout;

  /** The interception listener's port, on loopback only (qits-2644). */
  @ConfigProperty(name = "qits.egress.tls.port", defaultValue = "8443")
  int tlsPort;

  /**
   * TEST ONLY: a PEM file of the certificates the upstream pools trust INSTEAD of the JVM's — the
   * suites' fake https upstream. Empty in a deployment, where an upstream is verified against the
   * JVM's public trust store and nothing else.
   */
  @ConfigProperty(name = "qits.egress.test.upstream-trust")
  Optional<String> upstreamTrust;

  private HttpServer server;

  /** The interception listener: TLS ended inside {@code CONNECT} tunnels (qits-2644). */
  private HttpServer intercepting;

  private final Interception interception = new Interception();

  /** The forwards' callers, by the loopback port their splice comes from (qits-2654). */
  private final ForwardedCallers forwards = new ForwardedCallers();

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
    intercepting =
        vertx
            .createHttpServer(Interception.options(ConnectTunnel.LOOPBACK, tlsPort, leaves))
            // No inFlight.accept here: a tunnel the 8081 listener admitted is served whatever the
            // drain says — its CONNECT is the call in flight the drain waits for.
            .requestHandler(this::intercepted)
            .listen()
            .toCompletionStage()
            .toCompletableFuture()
            .get(30, TimeUnit.SECONDS);
    LOG.infof(
        "the egress interception listener listens on %s:%d",
        ConnectTunnel.LOOPBACK, intercepting.actualPort());
  }

  private Pool pool(String name) {
    HttpClientOptions options = upstreamTrust(ProxyClients.proxyClientOptions(5_000));
    UpstreamPools pools = new UpstreamPools(name, options.getMaxPoolSize());
    return new Pool(
        ProxyClients.proxyClient(vertx, options, pools::connected),
        ProxyClients.proxyClient(
            vertx,
            upstreamTrust(ProxyClients.proxyClientOptions(5_000)).setKeepAlive(false),
            pools::connected),
        pools);
  }

  /**
   * The JVM's trust store, untouched — unless the suites name a fake upstream's CA
   * ({@code qits.egress.test.upstream-trust}). Never trust-all, never the platform's own anchors.
   */
  private HttpClientOptions upstreamTrust(HttpClientOptions options) {
    upstreamTrust
        .filter(path -> !path.isBlank())
        .ifPresent(path -> options.setTrustOptions(new PemTrustOptions().addCertPath(path)));
    return options;
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

  /** The interception listener's port, on {@code 127.0.0.1}. */
  int tlsPort() {
    return intercepting.actualPort();
  }

  /** The forwards' callers, for {@link ForwardDoor}. */
  ForwardedCallers forwards() {
    return forwards;
  }

  /** How many intercepted tunnels are open. */
  int interceptedTunnels() {
    return interception.open();
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
    ForwardedCallers.Forward forward = forwards.of(request.connection());
    if (forward != null) {
      audit.forwarded();
    }
    String presented =
        request.getHeader(
            form == Form.GATEWAY ? HttpHeaders.AUTHORIZATION : HttpHeaders.PROXY_AUTHORIZATION);
    String credential = form == Form.GATEWAY ? presented : ProxyCredential.bearer(presented);
    // Over a forward, a request that names no credential of its own is the forward's caller; one
    // that does (a Claude launch sends the agent's own token) is whoever that credential says.
    boolean asForwarded = forward != null && presented == null;
    String bearer = asForwarded ? forward.bearer() : rawBearer(credential);
    (asForwarded ? Future.succeededFuture(forward.verdict()) : callers.identify(credential))
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
              Call call = new Call(request, audit, exchange, verdict, bearer, forward != null);
              switch (form) {
                case GATEWAY -> route(call, gateway);
                case ABSOLUTE -> absolute(call, absolute);
                case CONNECT -> connect(call);
              }
            });
  }

  /**
   * One identified call on its way: the request, its audit line and exchange, who the caller is and
   * the bearer it presented (a platform route exchanges it; nothing else reads it), and whether it
   * came over a forward.
   */
  record Call(
      HttpServerRequest request,
      AuditLine audit,
      InFlight.Exchange exchange,
      CallerIdentity.Verdict verdict,
      String bearer,
      boolean forwarded) {}

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
    GrantRoute route = table.route(verdict.principal(), gateway.route());
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
    // A plain-http target no route covers may pass through for a principal with a project; never
    // an https one (a proxy client tunnels those with CONNECT), so never a request inside a tunnel.
    boolean mayPass = target.scheme().equals("http") && passthrough.applies(verdict.principal());
    boolean claudeHost =
        target.scheme().equals("https")
            && claude.serves(verdict.principal(), target.host(), target.port());
    GrantIndex.Table table = grants.current();
    if (table == null && !mayPass && !claudeHost) {
      refuse(request, audit, 503, "no-table", error("no grant table yet"));
      return;
    }
    if (!Gateway.safe(target.path())) {
      refuse(request, audit, 400, "bad-path", error("a path with dot segments is refused"));
      return;
    }
    String method = request.method().name();
    GrantRoute route = target.match(routes(table, verdict));
    if (route == null && claudeHost) {
      claude(call, target);
      return;
    }
    if (route == null && mayPass) {
      passthroughHttp(call, target);
      return;
    }
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
   * {@code CONNECT host:port}: a tunnel, for an {@code https} route whose target is that host and
   * port and whose {@code methods} hold {@code CONNECT}. Its TLS is ended here (qits-2644): the
   * host's leaf is made sure of — held, or issued inline within {@code qits.egress.leaves.timeout}
   * — or the answer is 503, reason {@code no-leaf}; then {@code 200} and a splice to the
   * interception listener. The audit line is {@code method=CONNECT target=<host:port> path=-
   * ... tls=intercepted leafSerial=<hex>}, written when the tunnel closes.
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
    audit.target(authority.toString(), "-");
    boolean mayPass = passthrough.applies(verdict.principal());
    boolean claudeHost = claude.serves(verdict.principal(), authority.host(), authority.port());
    GrantIndex.Table table = grants.current();
    if (table == null && !mayPass && !claudeHost) {
      refuse(request, audit, 503, "no-table", error("no grant table yet"));
      return;
    }
    GrantRoute reached = null;
    GrantRoute granted = null;
    // By name, so which route a refusal names does not depend on a map's order.
    List<GrantRoute> candidates =
        routes(table, verdict).stream()
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
    if (granted == null && reached == null && claudeHost) {
      // A Claude host no route covers: intercepted all the same, its requests served by claude().
      audit.route(ClaudeHosts.ROUTE);
      interceptWithLeaf(call, authority, ClaudeHosts.ROUTE);
      return;
    }
    if (granted == null && reached == null && mayPass) {
      passthroughConnect(call, authority);
      return;
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
    interceptWithLeaf(call, authority, granted.name());
  }

  /**
   * The host's leaf made sure of — held, or issued inline within {@code qits.egress.leaves.timeout}
   * — or 503, reason {@code no-leaf}; then into the interception listener.
   */
  private void interceptWithLeaf(Call call, ConnectTunnel.Authority authority, String route) {
    HttpServerRequest request = call.request();
    AuditLine audit = call.audit();
    Context context = vertx.getOrCreateContext();
    leaves
        .issueNow(authority.host())
        .whenComplete(
            (leaf, failure) ->
                context.runOnContext(
                    v -> {
                      if (failure != null || leaf == null) {
                        LOG.warnf(
                            "no leaf for a CONNECT to %s: %s",
                            authority,
                            failure == null ? "none" : failure.toString());
                        refuse(request, audit, 503, "no-leaf", error("no certificate for the host yet"));
                        return;
                      }
                      intercept(call, authority, route, leaf);
                    }));
  }

  /** A granted {@code CONNECT} whose host's leaf is held: {@code 200}, and into the listener. */
  private void intercept(Call call, ConnectTunnel.Authority authority, String route, Leaf leaf) {
    AuditLine audit = call.audit();
    audit.allow();
    audit.leafSerial(leaf.serial());
    tunnels.open(
        call.request(),
        intercepting.actualPort(),
        interception,
        new Interception.Tunnel(call.verdict(), authority, route, call.forwarded()),
        call.exchange(),
        audit);
  }

  /**
   * A request inside an intercepted tunnel, on the loopback listener: the caller is the tunnel's,
   * looked up by the connection's remote port; the target origin is {@code https://<SNI host>:<the
   * CONNECT's port>}; then the absolute-form path — route by origin and base path, the inner
   * method checked, credentials stripped, secret injected, answer scrubbed — and an audit line with
   * {@code tls=intercepted}. A {@code Host} that is not the SNI host is 421.
   */
  void intercepted(HttpServerRequest request) {
    request.pause();
    String path = request.path() == null || request.path().isEmpty() ? "/" : request.path();
    AuditLine audit = new AuditLine(request.method().name(), path).intercepted();
    HttpServerResponse response = request.response();
    InFlight.Exchange exchange = inFlight.open(request, () -> audit.write(response.getStatusCode()));
    if (exchange == null) {
      return;
    }
    Interception.Tunnel tunnel =
        request.connection() == null || request.connection().remoteAddress() == null
            ? null
            : interception.at(request.connection().remoteAddress().port());
    if (tunnel == null) {
      refuse(request, audit, 403, "no-tunnel", error("not a tunnel this proxy opened"));
      return;
    }
    audit.principal(tunnel.verdict().principal());
    if (tunnel.forwarded()) {
      audit.forwarded();
    }
    String sni = Interception.sniHost(request.connection());
    audit.target(sni == null ? tunnel.authority().host() : sni, path);
    if (sni == null
        || !sni.equals(tunnel.authority().host())
        || !Interception.hostMatches(
            request.getHeader(HttpHeaders.HOST), sni, tunnel.authority().port())) {
      refuse(
          request,
          audit,
          421,
          "misdirected",
          error("the request's Host is not the tunnel's host"));
      return;
    }
    String query = request.query();
    absolute(
        new Call(request, audit, exchange, tunnel.verdict(), null, tunnel.forwarded()),
        new AbsoluteTarget(
            "https",
            sni,
            tunnel.authority().port(),
            path,
            query == null || query.isEmpty() ? null : query));
  }

  /**
   * A request to a Claude host no route covers, for a principal with a project ({@link
   * ClaudeHosts}): Claude Code's placeholder refresh answered here, a placeholder bearer swapped for
   * the held access token — or 503 when none is held — and the answer scrubbed of the held tokens.
   * Audited {@code route=claude}.
   */
  private void claude(Call call, AbsoluteTarget target) {
    HttpServerRequest request = call.request();
    AuditLine audit = call.audit();
    audit.route(ClaudeHosts.ROUTE);
    String uri =
        target.query() == null || target.query().isEmpty()
            ? target.path()
            : target.path() + "?" + target.query();
    boolean placeholder =
        ClaudeHosts.isPlaceholder(request.getHeader(HttpHeaders.AUTHORIZATION));
    long length = contentLength(request);
    if (ClaudeHosts.isTokenRequest(request.method(), target.host(), target.path())
        && length >= 0
        && length <= ClaudeHosts.TOKEN_BODY_LIMIT) {
      // Read whole (it is small) to tell the placeholder's refresh from a real one.
      request
          .body()
          .onComplete(
              read -> {
                if (read.failed()) {
                  refuse(request, audit, 400, "bad-body", error("the request body cannot be read"));
                  return;
                }
                Buffer body = read.result();
                if (ClaudeHosts.placeholderRefresh(
                    request.getHeader(HttpHeaders.CONTENT_TYPE), body)) {
                  placeholderRefresh(request, audit);
                  return;
                }
                claudeForward(call, target, uri, placeholder, body);
              });
      request.resume();
      return;
    }
    claudeForward(call, target, uri, placeholder, null);
  }

  /** The placeholder's refresh: the placeholder again, with the held scopes; 503 with none held. */
  private void placeholderRefresh(HttpServerRequest request, AuditLine audit) {
    ClaudeCredentials.Held held = claudeCredentials.current();
    if (held == null) {
      refuse(request, audit, 503, "no-claude-credential", error("no claude credential held"));
      return;
    }
    audit.allow().reason("claude-refresh");
    HttpServerResponse response = request.response();
    if (response.ended() || response.closed()) {
      return;
    }
    response
        .setStatusCode(200)
        .putHeader(HttpHeaders.CONTENT_TYPE, "application/json")
        .putHeader(HttpHeaders.CACHE_CONTROL, "no-store")
        .end(ClaudeHosts.placeholderToken(held.scopes()).encode());
  }

  /**
   * A Claude host's request on: the placeholder swapped (503 with none held), the caller's own
   * credentials otherwise untouched, the held tokens scrubbed out of the answer — {@code
   * Set-Cookie} dropped only when the held login was injected.
   *
   * @param body the request body when it was read whole, else null
   */
  private void claudeForward(
      Call call, AbsoluteTarget target, String uri, boolean placeholder, Buffer body) {
    HttpServerRequest request = call.request();
    AuditLine audit = call.audit();
    ClaudeCredentials.Held held = claudeCredentials.current();
    if (placeholder && held == null) {
      refuse(request, audit, 503, "no-claude-credential", error("no claude credential held"));
      return;
    }
    audit.allow();
    String accessToken = placeholder ? held.accessToken() : null;
    Scrubber scrubber = held == null ? null : Scrubber.of(held.accessToken(), held.refreshToken());
    RequestOptions options = claude.origin(target.host());
    UpstreamOrigin dialled = new UpstreamOrigin(options.getHost(), options.getPort());
    String authority = target.host() + ":" + target.port();
    if (isWebSocketUpgrade(request)) {
      audit.reason("websocket");
      webSockets.handle(
          request,
          options,
          uri,
          ClaudeOutbound.handshake(request.headers(), accessToken),
          scrubber,
          accessToken != null,
          call.exchange(),
          audit);
      return;
    }
    Pool pool = isStream(request) ? stream : ordinary;
    HttpProxy proxy =
        HttpProxy.reverseProxy(new ProxyOptions().setSupportWebSocket(false), pool.client())
            .origin(origin(options, dialled, authority, pool, pool.client()))
            .addInterceptor(new ClaudeOutbound(target.host(), uri, accessToken, body, audit));
    if (scrubber != null) {
      proxy.addInterceptor(new ResponseScrub(scrubber, accessToken != null, audit));
    }
    proxy
        .addInterceptor(new EdgeHopByHop())
        .addInterceptor(new EdgeRequestFraming())
        .addInterceptor(
            new UpstreamRetry(authority, origin(options, dialled, authority, pool, pool.fresh())))
        .handle(request);
  }

  /** The request's {@code Content-Length}, or -1 when it names none or no number. */
  private static long contentLength(HttpServerRequest request) {
    String length = request.getHeader(HttpHeaders.CONTENT_LENGTH);
    if (length == null) {
      return -1;
    }
    try {
      return Long.parseLong(length.trim());
    } catch (NumberFormatException e) {
      return -1;
    }
  }

  /** The routes the caller holds in {@code table}, none when there is no table. */
  private static Collection<GrantRoute> routes(GrantIndex.Table table, CallerIdentity.Verdict verdict) {
    return table == null ? List.of() : table.routes(verdict.principal());
  }

  /**
   * A {@code CONNECT} no route reaches, for a principal with a project: a BLIND splice to the
   * checked address ({@link Passthrough}), or {@code 403 passthrough refused}. Audited {@code
   * decision=ALLOW route=- ... passthrough=true} when the tunnel closes.
   */
  private void passthroughConnect(Call call, ConnectTunnel.Authority authority) {
    HttpServerRequest request = call.request();
    AuditLine audit = call.audit();
    if (!passthrough.connectPort(authority.port())) {
      refusePassthrough(call, Passthrough.PORT, authority.toString());
      return;
    }
    passthrough
        .check(authority.host(), authority.port())
        .onComplete(
            result -> {
              Passthrough.Outcome outcome =
                  result.succeeded() ? result.result() : Passthrough.Outcome.refused(Passthrough.UNRESOLVED);
              if (outcome.checked() == null) {
                refusePassthrough(call, outcome.refusal(), authority.toString());
                return;
              }
              audit.allow().passthrough();
              tunnels.blind(request, outcome.checked().dial(), authority, call.exchange(), audit);
            });
  }

  /**
   * An absolute-form {@code http://} request no route covers, for a principal with a project: sent
   * on as it came to the checked address ({@link Passthrough}, {@link PassthroughOutbound}) — the
   * caller's own {@code Authorization} and {@code Cookie} kept — or {@code 403 passthrough
   * refused}.
   */
  private void passthroughHttp(Call call, AbsoluteTarget target) {
    HttpServerRequest request = call.request();
    AuditLine audit = call.audit();
    if (!passthrough.httpPort(target.port())) {
      refusePassthrough(call, Passthrough.PORT, target.origin());
      return;
    }
    passthrough
        .check(target.host(), target.port())
        .onComplete(
            result -> {
              Passthrough.Outcome outcome =
                  result.succeeded() ? result.result() : Passthrough.Outcome.refused(Passthrough.UNRESOLVED);
              if (outcome.checked() == null) {
                refusePassthrough(call, outcome.refusal(), target.origin());
                return;
              }
              audit.allow().passthrough();
              String uri =
                  target.query() == null || target.query().isEmpty()
                      ? target.path()
                      : target.path() + "?" + target.query();
              RequestOptions options =
                  new RequestOptions()
                      .setHost(target.host())
                      .setPort(target.port())
                      .setServer(outcome.checked().dial())
                      .setSsl(false)
                      .setConnectTimeout(ProxyClients.ACQUIRE_TIMEOUT_MS);
              UpstreamOrigin dialled = new UpstreamOrigin(target.host(), target.port());
              String authority = target.host() + ":" + target.port();
              Pool pool = isStream(request) ? stream : ordinary;
              HttpProxy.reverseProxy(new ProxyOptions().setSupportWebSocket(false), pool.client())
                  .origin(origin(options, dialled, authority, pool, pool.client()))
                  .addInterceptor(new PassthroughOutbound(target, uri, audit))
                  .addInterceptor(new EdgeHopByHop())
                  .addInterceptor(new EdgeRequestFraming())
                  .addInterceptor(
                      new UpstreamRetry(authority, origin(options, dialled, authority, pool, pool.fresh())))
                  .handle(request);
            });
  }

  /**
   * A passthrough refusal: 403 {@code {"error":"passthrough refused","reason":…}}, audit reason
   * {@code passthrough-<reason>}; a name that does not resolve is 502.
   */
  private static void refusePassthrough(Call call, String reason, String target) {
    boolean unresolved = Passthrough.UNRESOLVED.equals(reason);
    refuse(
        call.request(),
        call.audit(),
        unresolved ? 502 : 403,
        "passthrough-" + reason,
        new JsonObject()
            .put("error", unresolved ? "the target cannot be resolved" : "passthrough refused")
            .put("reason", reason)
            .put("principal", call.verdict().principal().toString())
            .put("target", target));
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
    return origin(
        originOptions(route),
        new UpstreamOrigin(route.host(), route.dialPort()),
        route.authority(),
        pool,
        client);
  }

  /** {@link #origin(GrantRoute, Pool, HttpClient)} for any request options. */
  private static OriginRequestProvider origin(
      RequestOptions options, UpstreamOrigin dialled, String authority, Pool pool, HttpClient client) {
    return context -> {
      UpstreamLease lease = UpstreamLease.of(context.request().proxiedRequest());
      long since = pool.pools().acquiring();
      Future<HttpClientRequest> request = client.request(new RequestOptions(options));
      return request
          .onSuccess(granted -> pool.pools().granted(dialled, since, granted, lease, false))
          .onFailure(
              failure -> {
                pool.pools().failed(dialled, since);
                LOG.warnf(
                    "no upstream connection to %s from the %s pool: %s",
                    authority, pool.pools().pool(), failure.toString());
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
