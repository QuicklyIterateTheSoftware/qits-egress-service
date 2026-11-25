package eu.wohlben.qits.egress.proxy;

import eu.wohlben.qits.egress.identity.CallerIdentity;
import io.vertx.core.Vertx;
import io.vertx.core.http.HttpHeaders;
import io.vertx.core.http.HttpServerRequest;
import io.vertx.core.http.HttpServerResponse;
import io.vertx.core.http.ServerWebSocket;
import io.vertx.core.json.JsonObject;
import io.vertx.core.net.NetClient;
import io.vertx.core.net.NetClientOptions;
import io.vertx.core.net.NetSocket;
import io.vertx.ext.web.Router;
import io.vertx.ext.web.RoutingContext;
import jakarta.annotation.PostConstruct;
import jakarta.enterprise.context.ApplicationScoped;
import jakarta.enterprise.event.Observes;
import jakarta.inject.Inject;
import java.util.concurrent.atomic.AtomicBoolean;
import org.jboss.logging.Logger;

/**
 * <b>{@code GET /egress/api/forward}</b> (epic qits-2525, qits-2654): the proxy listener, reached
 * through the edge. A container on a runner lease has no qits-net and cannot dial {@code
 * ${QITS_ENVIRONMENT}-qits-egress:8081}; the edges pass websocket upgrades on every route but no
 * layer-4 traffic. So {@code qits egress forward} in the container opens one websocket here per TCP
 * connection its tools make, and this door splices it to the proxy listener on {@code 127.0.0.1}.
 * Policy and identity stay with the listener ({@link EgressProxy}).
 *
 * <ol>
 *   <li>A Vert.x route on the Quarkus HTTP server (8080, behind the public edge), registered on
 *       {@link Router}: the service has no websockets extension, and needs none.
 *   <li>{@code Authorization: Bearer <qits bearer>} on the upgrade, resolved by {@link
 *       CallerIdentity} — a JWT offline, a {@code qits_tok_} by introspection. Without a good one,
 *       {@code 401} before the upgrade; an idp that cannot be reached, {@code 503}. Any principal
 *       may open a forward: what it can do is decided per request on the listener. A request that
 *       is no websocket upgrade is {@code 400}.
 *   <li>Then a connection to the listener's own port on {@code 127.0.0.1}, its LOCAL port
 *       registered in {@link ForwardedCallers} with the caller, the upgrade answered {@code 101},
 *       and the two spliced with back-pressure: each data frame's bytes to the listener, the
 *       listener's bytes back as binary frames. A close or a failure on either side closes the
 *       other and releases the port. A listener that cannot be dialled is {@code 502}.
 * </ol>
 *
 * <p>The forward itself writes one audit line when it closes ({@code method=GET
 * path=/egress/api/forward status=101 reason=forward via=forward}), or when it is refused; each
 * request it carries writes its own, as on any connection, with {@code via=forward} added.
 *
 * <p><b>Shutdown</b>: a forward is in-flight work like any connection the listener holds. Its
 * requests and tunnels are exchanges of the listener's drain ({@link InFlight}), served to their end
 * and never cut early; Vert.x closes the sockets only after the drain and the linger.
 */
@ApplicationScoped
public class ForwardDoor {

  private static final Logger LOG = Logger.getLogger(ForwardDoor.class);

  static final String PATH = "/egress/api/forward";

  @Inject Vertx vertx;

  @Inject CallerIdentity callers;

  @Inject EgressProxy proxy;

  private NetClient loopback;

  @PostConstruct
  void open() {
    loopback =
        vertx.createNetClient(
            new NetClientOptions()
                .setConnectTimeout(ConnectTunnel.CONNECT_TIMEOUT_MS)
                .setTcpKeepAlive(true)
                // No idle timeout: a forward may carry a long, quiet tunnel.
                .setIdleTimeout(0));
  }

  void routes(@Observes Router router) {
    router.get(PATH).handler(this::forward);
  }

  void forward(RoutingContext context) {
    HttpServerRequest request = context.request();
    // Held until the caller is known and the listener dialled.
    request.pause();
    AuditLine audit = new AuditLine("GET", PATH).forwarded();
    String authorization = request.getHeader(HttpHeaders.AUTHORIZATION);
    callers
        .identify(authorization)
        .onComplete(
            result -> {
              CallerIdentity.Verdict verdict =
                  result.succeeded()
                      ? result.result()
                      : new CallerIdentity.Verdict(
                          null, 503, "idp-unreachable", "the identity provider cannot be reached");
              if (!verdict.admitted()) {
                if (verdict.status() == 401) {
                  request.response().putHeader("WWW-Authenticate", "Bearer realm=\"qits-egress\"");
                }
                refuse(request, audit, verdict.status(), verdict.reason(), verdict.message());
                return;
              }
              audit.principal(verdict.principal());
              if (!EgressProxy.isWebSocketUpgrade(request)) {
                refuse(request, audit, 400, "not-an-upgrade", "a websocket upgrade is required");
                return;
              }
              ForwardedCallers.Forward forward =
                  new ForwardedCallers.Forward(verdict, EgressProxy.rawBearer(authorization));
              splice(request, audit, forward);
            });
  }

  /** Dial the listener, register the caller under the connection's local port, upgrade, splice. */
  private void splice(HttpServerRequest request, AuditLine audit, ForwardedCallers.Forward forward) {
    ForwardedCallers forwards = proxy.forwards();
    loopback
        .connect(proxy.port(), ConnectTunnel.LOOPBACK)
        .onFailure(
            failure -> {
              LOG.errorf("no loopback connection to the proxy listener for a forward: %s", failure.toString());
              refuse(request, audit, 502, "listener-unreachable", "the proxy listener cannot be reached");
            })
        .onSuccess(
            outbound -> {
              int localPort = outbound.localAddress().port();
              forwards.register(localPort, forward);
              outbound.pause();
              request
                  .toWebSocket()
                  .onFailure(
                      failure -> {
                        forwards.release(localPort, forward);
                        outbound.close();
                        audit.deny("bad-upgrade");
                        audit.write(400);
                        LOG.warnf("a forward's upgrade failed: %s", failure.toString());
                      })
                  .onSuccess(
                      socket -> {
                        audit.allow().reason("forward");
                        audit.upstreamAnswered();
                        splice(
                            socket,
                            outbound,
                            () -> {
                              forwards.release(localPort, forward);
                              audit.write(101);
                            });
                        outbound.resume();
                      });
            });
  }

  /**
   * Both directions with back-pressure: each data frame's bytes to the listener, the listener's
   * bytes back as binary messages. A close or failure on either side closes the other; {@code
   * onClose} runs once.
   */
  static void splice(ServerWebSocket socket, NetSocket listener, Runnable onClose) {
    AtomicBoolean closed = new AtomicBoolean();
    Runnable done =
        () -> {
          if (closed.compareAndSet(false, true)) {
            onClose.run();
          }
        };
    socket.handler(
        data -> {
          listener.write(data);
          if (listener.writeQueueFull()) {
            socket.pause();
            listener.drainHandler(v -> socket.resume());
          }
        });
    listener.handler(
        data -> {
          socket.writeBinaryMessage(data);
          if (socket.writeQueueFull()) {
            listener.pause();
            socket.drainHandler(v -> listener.resume());
          }
        });
    socket.exceptionHandler(failure -> listener.close());
    listener.exceptionHandler(failure -> socket.close());
    socket.closeHandler(
        v -> {
          listener.close();
          done.run();
        });
    listener.closeHandler(
        v -> {
          if (!socket.isClosed()) {
            socket.close();
          }
          done.run();
        });
  }

  private static void refuse(
      HttpServerRequest request, AuditLine audit, int status, String reason, String message) {
    audit.deny(reason);
    audit.write(status);
    HttpServerResponse response = request.response();
    if (response.ended() || response.closed()) {
      return;
    }
    request.resume();
    response
        .setStatusCode(status)
        .putHeader(HttpHeaders.CONTENT_TYPE, "application/json")
        .end(new JsonObject().put("error", message).encode());
  }
}
