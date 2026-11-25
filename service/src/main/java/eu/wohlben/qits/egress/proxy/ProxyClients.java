package eu.wohlben.qits.egress.proxy;

import io.vertx.core.Handler;
import io.vertx.core.Vertx;
import io.vertx.core.http.HttpClient;
import io.vertx.core.http.HttpClientOptions;
import io.vertx.core.http.HttpConnection;

/**
 * The proxy client's options and the client itself — qits-edge's {@code EdgeRouter
 * proxyClientOptions} and {@code proxyClient}, copied with their reasons. Static so a test builds
 * the same client the gateway does.
 */
final class ProxyClients {

  /**
   * How long a request may wait for a pool slot to an origin, TCP connect included, before it
   * fails instead: a queued request behind a full pool fails loudly rather than hanging.
   */
  static final int ACQUIRE_TIMEOUT_MS = 30_000;

  private ProxyClients() {}

  /**
   * The upstream client's options. The two timeouts point in opposite directions on purpose.
   *
   * <p>TLS is per request ({@code RequestOptions.setSsl}), verifying the host name against the
   * JVM's trust store — the native image carries it with {@code quarkus.ssl.native=true}.
   */
  static HttpClientOptions proxyClientOptions(int connectTimeoutMs) {
    return new HttpClientOptions()
        .setKeepAlive(true)
        // Vert.x pools per origin and defaults to FIVE connections behind an unbounded wait queue;
        // every call to one third party shares one origin here.
        .setMaxPoolSize(256)
        // Bounded too: beyond this depth callers get an immediate failure (a 502), and the
        // acquisition timeout bounds the wait of those still queued.
        .setMaxWaitQueueSize(256)
        // Zero, no client-side idle timeout: a timeout here would sever exactly the long exchanges
        // (a slow download, an event stream) the gateway must carry.
        .setIdleTimeout(0)
        // SO_KEEPALIVE; the three timers that make it probe within a minute are set per channel by
        // UpstreamKeepAlive, since no Vert.x 4.5 transport applies them to a client socket.
        .setTcpKeepAlive(true)
        .setVerifyHost(true)
        .setConnectTimeout(connectTimeoutMs);
  }

  /**
   * The proxy client itself.
   *
   * <p><b>The pool options are passed explicitly, and that is load-bearing.</b> {@code
   * createHttpClient(options)} hands the builder {@code options.getPoolOptions()}; the builder
   * itself does not, and given only the client options it pools with {@code new PoolOptions()} —
   * five connections per origin behind an unbounded queue, silently undoing both bounds above.
   */
  static HttpClient proxyClient(
      Vertx vertx, HttpClientOptions options, Handler<HttpConnection> onConnect) {
    return vertx
        .httpClientBuilder()
        .with(options)
        .with(options.getPoolOptions())
        .withConnectHandler(onConnect)
        .build();
  }
}
