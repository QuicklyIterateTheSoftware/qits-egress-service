package eu.wohlben.qits.egress.proxy;

import eu.wohlben.qits.egress.grants.GrantRoute;
import io.vertx.core.Vertx;
import io.vertx.core.http.HttpHeaders;
import io.vertx.core.http.HttpServerRequest;
import io.vertx.core.http.HttpServerResponse;
import io.vertx.core.json.JsonObject;
import io.vertx.core.net.NetClient;
import io.vertx.core.net.NetClientOptions;
import java.util.Locale;
import org.jboss.logging.Logger;

/**
 * <b>A {@code CONNECT} tunnel, intercepted</b> (qits-2644): the caller's socket is spliced, with
 * back-pressure, to a fresh connection to the loopback interception listener ({@link Interception}),
 * where its TLS ends with the host's leaf and each request inside is served like an absolute-form
 * call — the route's secret injected, the answer scrubbed, every request audited. The bytes never
 * go to the target as they came: the target is dialled per inner request by the proxy's upstream
 * pool, over TLS verified against the JVM's public trust.
 *
 * <p>The tunnel's exchange is held until its sockets close, so a drain waits for it; the loopback
 * connection's {@link Interception.Tunnel} entry is removed at the same moment.
 */
final class ConnectTunnel {

  private static final Logger LOG = Logger.getLogger(ConnectTunnel.class);

  /** How long the TCP connect to the loopback listener may take. */
  static final int CONNECT_TIMEOUT_MS = 5_000;

  /** Where the interception listener is bound: loopback only. */
  static final String LOOPBACK = "127.0.0.1";

  private final NetClient client;

  ConnectTunnel(Vertx vertx) {
    this.client =
        vertx.createNetClient(
            new NetClientOptions()
                .setConnectTimeout(CONNECT_TIMEOUT_MS)
                .setTcpKeepAlive(true)
                // No idle timeout: a tunnel may carry a long, quiet exchange.
                .setIdleTimeout(0));
  }

  /**
   * {@code host:port} of a {@code CONNECT}, 443 when the port is left out.
   *
   * @param host lower case, without IPv6 brackets
   */
  record Authority(String host, int port) {

    static Authority parse(String uri) {
      if (uri == null || uri.isBlank() || uri.contains("/") || uri.contains("@")) {
        return null;
      }
      String host;
      String port = null;
      if (uri.startsWith("[")) {
        int close = uri.indexOf(']');
        if (close < 0) {
          return null;
        }
        host = uri.substring(1, close);
        if (close + 1 < uri.length()) {
          if (uri.charAt(close + 1) != ':') {
            return null;
          }
          port = uri.substring(close + 2);
        }
      } else {
        int colon = uri.lastIndexOf(':');
        host = colon < 0 ? uri : uri.substring(0, colon);
        port = colon < 0 ? null : uri.substring(colon + 1);
      }
      if (host.isEmpty()) {
        return null;
      }
      try {
        int number = port == null ? 443 : Integer.parseInt(port);
        if (number <= 0 || number > 65_535) {
          return null;
        }
        return new Authority(host.toLowerCase(Locale.ROOT), number);
      } catch (NumberFormatException notAPort) {
        return null;
      }
    }

    /**
     * Whether a route's target is this host and port. Only an {@code https} target is tunnelled —
     * the tunnel's TLS is ended here — and a platform route never is.
     */
    boolean reaches(GrantRoute route) {
      return !route.isPlatform()
          && route.ssl()
          && route.targetProblem() == null
          && route.host() != null
          && route.host().equalsIgnoreCase(host)
          && route.dialPort() == port;
    }

    @Override
    public String toString() {
      return (host.contains(":") ? "[" + host + "]" : host) + ":" + port;
    }
  }

  /**
   * Dial the loopback listener, record the tunnel under the connection's local port, then answer
   * {@code 200 Connection Established} and splice. A listener that does not answer is 502.
   */
  void open(
      HttpServerRequest request,
      int loopbackPort,
      Interception interception,
      Interception.Tunnel tunnel,
      InFlight.Exchange exchange,
      AuditLine audit) {
    client
        .connect(loopbackPort, LOOPBACK)
        .onFailure(
            failure -> {
              LOG.errorf("no loopback connection for a tunnel to %s: %s", tunnel.authority(), failure.toString());
              request.resume();
              HttpServerResponse response = request.response();
              if (!response.ended() && !response.closed()) {
                response
                    .setStatusCode(502)
                    .putHeader(HttpHeaders.CONTENT_TYPE, "application/json")
                    .end(new JsonObject().put("error", "the tunnel cannot be opened").encode());
              }
            })
        .onSuccess(
            outbound -> {
              int localPort = outbound.localAddress().port();
              interception.register(localPort, tunnel);
              audit.upstreamAnswered();
              outbound.pause();
              exchange.splice();
              request.resume();
              request.response().setStatusMessage("Connection Established");
              request
                  .toNetSocket()
                  .onFailure(
                      failure -> {
                        interception.release(localPort, tunnel);
                        outbound.close();
                        exchange.settle();
                        LOG.errorf(failure, "could not take over the caller's connection for a tunnel to %s", tunnel.authority());
                      })
                  .onSuccess(
                      inbound -> {
                        WebSocketSplice.splice(
                            inbound, outbound, exchange, () -> interception.release(localPort, tunnel));
                        outbound.resume();
                      });
            });
  }
}
