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
 * <b>A {@code CONNECT} tunnel</b> to a granted route's host and port: the bytes are spliced both
 * ways, with back-pressure, until either side closes. Nothing is injected and nothing is scrubbed —
 * they are the caller's TLS to the third party, opaque here — so a route grants {@code CONNECT}
 * only on purpose ({@code methods: [CONNECT]}). The tunnel's exchange is held until its sockets
 * close, so a drain waits for it.
 */
final class ConnectTunnel {

  private static final Logger LOG = Logger.getLogger(ConnectTunnel.class);

  /** How long the TCP connect to the target may take. */
  static final int CONNECT_TIMEOUT_MS = 5_000;

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

    /** Whether a route's target is this host and port. A platform route is never tunnelled. */
    boolean reaches(GrantRoute route) {
      return !route.isPlatform()
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

  /** Dial the target, then answer {@code 200} and splice; a target that does not answer is 502. */
  void open(HttpServerRequest request, Authority authority, InFlight.Exchange exchange, AuditLine audit) {
    client
        .connect(authority.port(), authority.host())
        .onFailure(
            failure -> {
              LOG.warnf("no tunnel to %s: %s", authority, failure.toString());
              request.resume();
              HttpServerResponse response = request.response();
              if (!response.ended() && !response.closed()) {
                response
                    .setStatusCode(502)
                    .putHeader(HttpHeaders.CONTENT_TYPE, "application/json")
                    .end(new JsonObject().put("error", "the target cannot be reached").encode());
              }
            })
        .onSuccess(
            outbound -> {
              audit.upstreamAnswered();
              outbound.pause();
              exchange.splice();
              request.resume();
              request
                  .toNetSocket()
                  .onFailure(
                      failure -> {
                        outbound.close();
                        exchange.settle();
                        LOG.errorf(failure, "could not take over the caller's connection for a tunnel to %s", authority);
                      })
                  .onSuccess(
                      inbound -> {
                        WebSocketSplice.splice(inbound, outbound, exchange);
                        outbound.resume();
                      });
            });
  }
}
