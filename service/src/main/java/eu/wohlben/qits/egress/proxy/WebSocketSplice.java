package eu.wohlben.qits.egress.proxy;

import io.vertx.core.MultiMap;
import io.vertx.core.http.HttpClient;
import io.vertx.core.http.HttpClientRequest;
import io.vertx.core.http.HttpClientResponse;
import io.vertx.core.http.HttpHeaders;
import io.vertx.core.http.HttpMethod;
import io.vertx.core.http.HttpServerRequest;
import io.vertx.core.http.HttpServerResponse;
import io.vertx.core.http.RequestOptions;
import io.vertx.core.json.JsonObject;
import io.vertx.core.net.NetSocket;
import java.util.Map;
import java.util.concurrent.TimeoutException;
import org.jboss.logging.Logger;

/**
 * <b>A WebSocket through a granted route</b>: the handshake goes upstream with exactly what an
 * ordinary call carries — the caller's credentials and platform headers removed, the route's secret
 * (or a platform route's exchanged bearer) injected — and once the upstream answers {@code 101}, the
 * two sockets are spliced. qits-edge's {@code EdgeWebSocketUpgrade}, adapted.
 *
 * <p><b>Why not {@code vertx-http-proxy}'s own upgrade path</b>: it skips the interceptor chain, so
 * the caller's credentials would leave and nothing would be injected. It is off ({@code
 * setSupportWebSocket(false)}) and this class is the only way an upgrade leaves the gateway.
 *
 * <p><b>Every path that does not end in a spliced socket gives the upstream connection back</b> by
 * closing it — a connection that carried a handshake is not one to pool — and answers the caller:
 * an upstream that refuses the upgrade is relayed as its own status, a failed acquisition as 502
 * (503 when the pool is full). No handler is ever registered on the inbound request: a WebSocket
 * client sends nothing before the {@code 101}, and {@code toNetSocket()} takes the whole connection
 * over.
 *
 * <p><b>What is NOT scrubbed</b>: the frames. They are spliced as bytes, and replacing bytes inside
 * a frame would break its length. The upstream's {@code 101} headers are scrubbed like any answer.
 *
 * <p><b>The stream pool</b> — a socket holds its connection for as long as it is open. Its lease
 * ends when the channel closes and not before; the {@link InFlight.Exchange} too, so a drain waits
 * for the socket rather than for the handshake.
 */
final class WebSocketSplice {

  private static final Logger LOG = Logger.getLogger(WebSocketSplice.class);

  private final HttpClient client;

  private final UpstreamPools pools;

  /**
   * @param client the stream pool's client
   * @param pools that client's counts
   */
  WebSocketSplice(HttpClient client, UpstreamPools pools) {
    this.client = client;
    this.pools = pools;
  }

  /**
   * One handshake, the inbound request paused.
   *
   * @param origin where the handshake goes: host, port, TLS and the acquisition bound
   * @param uri the upstream request target
   * @param outbound the headers the upstream sees, prepared as for an ordinary call
   * @param scrubber the route's scrubber for the {@code 101} headers, or null for none
   */
  void handle(
      HttpServerRequest request,
      RequestOptions origin,
      String uri,
      MultiMap outbound,
      Scrubber scrubber,
      InFlight.Exchange exchange,
      AuditLine audit) {
    UpstreamOrigin dialled = new UpstreamOrigin(origin.getHost(), origin.getPort());
    UpstreamLease lease = UpstreamLease.of(request);
    long since = pools.acquiring();
    client
        .request(origin)
        .onFailure(
            failure -> {
              pools.failed(dialled, since);
              LOG.warnf("no upstream connection to %s for a WebSocket upgrade: %s", dialled, failure);
              refuse(request, saturated(failure) ? 503 : 502);
            })
        .onSuccess(
            handshake -> {
              pools.granted(dialled, since, handshake, lease, true);
              forward(request, dialled, uri, outbound, scrubber, handshake, exchange, audit);
            });
  }

  private static boolean saturated(Throwable failure) {
    return failure instanceof io.vertx.core.http.ConnectionPoolTooBusyException
        || failure instanceof TimeoutException;
  }

  private void forward(
      HttpServerRequest request,
      UpstreamOrigin dialled,
      String uri,
      MultiMap outbound,
      Scrubber scrubber,
      HttpClientRequest handshake,
      InFlight.Exchange exchange,
      AuditLine audit) {
    try {
      handshake.setMethod(HttpMethod.GET);
      handshake.setURI(uri);
      for (Map.Entry<String, String> header : outbound) {
        if (HttpHeaders.HOST.toString().equalsIgnoreCase(header.getKey())
            || HttpHeaders.CONNECTION.toString().equalsIgnoreCase(header.getKey())) {
          continue;
        }
        handshake.headers().add(header.getKey(), header.getValue());
      }
      handshake.headers().set(HttpHeaders.CONNECTION, HttpHeaders.UPGRADE);
      handshake
          .connect()
          .onFailure(
              failure -> {
                close(handshake);
                LOG.warnf("the WebSocket handshake to %s failed: %s", dialled, failure);
                refuse(request, 502);
              })
          .onSuccess(
              response ->
                  upgraded(request, dialled, handshake, response, scrubber, exchange, audit));
    } catch (RuntimeException failure) {
      close(handshake);
      throw failure;
    }
  }

  private void upgraded(
      HttpServerRequest request,
      UpstreamOrigin dialled,
      HttpClientRequest handshake,
      HttpClientResponse response,
      Scrubber scrubber,
      InFlight.Exchange exchange,
      AuditLine audit) {
    audit.upstreamAnswered();
    try {
      if (response.statusCode() != 101) {
        // The upstream refused the upgrade; the caller learns its status. Closed rather than pooled.
        close(handshake);
        refuse(request, response.statusCode());
        return;
      }
      HttpServerResponse accepted = request.response();
      accepted.setStatusCode(101);
      accepted.headers().addAll(response.headers());
      if (scrubber != null) {
        scrubber.scrub(accepted.headers());
      }
      exchange.splice();
      // Taken now, while this is still the response's own callback: what the upstream sends from
      // here on is the socket's, held until the splice reads it.
      NetSocket outbound = response.netSocket();
      outbound.pause();
      request.resume();
      request
          .toNetSocket()
          .onFailure(
              failure -> {
                close(handshake);
                exchange.settle();
                LOG.errorf(failure, "could not take over the caller's connection for a socket to %s", dialled);
              })
          .onSuccess(
              inbound -> {
                splice(inbound, outbound, exchange);
                outbound.resume();
              });
    } catch (RuntimeException failure) {
      close(handshake);
      throw failure;
    }
  }

  /** Both directions with back-pressure; a close on either side closes the other. */
  static void splice(NetSocket inbound, NetSocket outbound, InFlight.Exchange exchange) {
    pipe(inbound, outbound);
    pipe(outbound, inbound);
    inbound.exceptionHandler(failure -> outbound.close());
    outbound.exceptionHandler(failure -> inbound.close());
    inbound.closeHandler(
        v -> {
          outbound.close();
          exchange.settle();
        });
    outbound.closeHandler(
        v -> {
          inbound.close();
          exchange.settle();
        });
  }

  /** One direction: write, pause the source while the target's queue is full. */
  private static void pipe(NetSocket from, NetSocket to) {
    from.handler(
        data -> {
          to.write(data);
          if (to.writeQueueFull()) {
            from.pause();
            to.drainHandler(v -> from.resume());
          }
        });
  }

  private static void close(HttpClientRequest handshake) {
    try {
      if (handshake.connection() != null) {
        handshake.connection().close();
      } else {
        handshake.reset();
      }
    } catch (RuntimeException failure) {
      LOG.errorf(failure, "could not release an upstream connection after a failed upgrade");
    }
  }

  private static void refuse(HttpServerRequest request, int status) {
    request.resume();
    HttpServerResponse response = request.response();
    if (!response.ended() && !response.headWritten() && !response.closed()) {
      response
          .setStatusCode(status)
          .putHeader(HttpHeaders.CONTENT_TYPE, "application/json")
          .end(new JsonObject().put("error", "the WebSocket upgrade failed").encode());
    }
  }
}
