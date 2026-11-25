package eu.wohlben.qits.egress.proxy;

import io.vertx.core.http.HttpConnection;
import io.vertx.core.http.HttpServerRequest;
import io.vertx.core.http.HttpServerResponse;
import java.time.Duration;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.function.IntSupplier;
import org.jboss.logging.Logger;

/**
 * <b>What the proxy listener is carrying right now, and the drain that waits for it</b>.
 *
 * <p>qits-edge leans on Quarkus' HTTP drain ({@code GracefulShutdownFilter}) and has to repair its
 * count where Vert.x never reports an exchange over ({@code DrainCount}). The proxy listener is a
 * plain Vert.x server, which Quarkus does not count at all, so it counts itself, from three
 * signals, whichever comes first, each settling an {@link Exchange} once:
 *
 * <ul>
 *   <li>the response's end or close handler — an ordinary exchange;
 *   <li>the CONNECTION's close — the backstop for a response the proxy reset, whose handlers Vert.x
 *       skips (on HTTP/1.x {@code reset()} marks the response closed before the connection goes);
 *   <li>for a spliced socket (a WebSocket's {@code 101}, a {@code CONNECT} tunnel), only the
 *       socket's close: past {@code toNetSocket()} the response's handlers mean nothing, so the
 *       splice {@linkplain Exchange#splice() takes the exchange over}.
 * </ul>
 *
 * <p><b>The drain</b> ({@link #drain}): from its start, a NEW connection is closed as it arrives
 * (swarm has taken the task out of the VIP during the shutdown delay, so one is rare and goes
 * elsewhere on its retry), while every exchange already running — and every request that arrives
 * on a connection already open, which is a call somebody has sent — is served to its end. It waits
 * until nothing is in flight or the timeout passes. Nothing is closed early, streams and tunnels
 * included: a restart must drop no running call. After it returns, a request on a connection still
 * open has its connection closed unanswered, so its client retries on a fresh one, elsewhere.
 */
final class InFlight {

  private static final Logger LOG = Logger.getLogger(InFlight.class);

  /** How often the drain looks at the count. */
  static final long POLL_MS = 50;

  private final AtomicInteger count = new AtomicInteger();

  /** What each open connection is carrying; the connection's close settles all of it. */
  private final Map<HttpConnection, Set<Exchange>> carried = new ConcurrentHashMap<>();

  private volatile boolean draining;

  private volatile boolean closed;

  /**
   * One exchange: open from its arrival until settled.
   *
   * @param onSettled run once, when the exchange is over (the audit line)
   */
  final class Exchange {

    private final AtomicBoolean settled = new AtomicBoolean();

    private final AtomicBoolean spliced = new AtomicBoolean();

    private final Runnable onSettled;

    private final Set<Exchange> carrier;

    private Exchange(Runnable onSettled, Set<Exchange> carrier) {
      this.onSettled = onSettled;
      this.carrier = carrier;
    }

    /** The response ended or closed: over, unless a splice has taken it over. */
    void responseDone() {
      if (!spliced.get()) {
        settle();
      }
    }

    /** A socket splice takes the exchange over: only {@link #settle} ends it from now. */
    void splice() {
      spliced.set(true);
    }

    /** Over, whatever its state. Idempotent. */
    void settle() {
      if (settled.compareAndSet(false, true)) {
        count.decrementAndGet();
        if (carrier != null) {
          carrier.remove(this);
        }
        try {
          onSettled.run();
        } catch (RuntimeException failure) {
          LOG.errorf(failure, "settling an exchange failed");
        }
      }
    }

    boolean settled() {
      return settled.get();
    }
  }

  /**
   * A new connection: tracked, so its close settles what it carried; refused while draining.
   *
   * @return whether the connection may carry requests
   */
  boolean accept(HttpConnection connection) {
    if (draining) {
      connection.close();
      return false;
    }
    carriedBy(connection);
    return true;
  }

  /**
   * One arriving request, or null when the drain is over and the request's connection is closed
   * instead of answered.
   */
  Exchange open(HttpServerRequest request, Runnable onSettled) {
    if (closed) {
      request.connection().close();
      return null;
    }
    count.incrementAndGet();
    HttpConnection connection = request.connection();
    Set<Exchange> carrier = connection == null ? null : carriedBy(connection);
    Exchange exchange = new Exchange(onSettled, carrier);
    if (carrier != null) {
      carrier.add(exchange);
    }
    HttpServerResponse response = request.response();
    response.endHandler(v -> exchange.responseDone());
    response.closeHandler(v -> exchange.responseDone());
    response.exceptionHandler(e -> exchange.responseDone());
    return exchange;
  }

  /**
   * The set of exchanges one connection carries, made on its first sight. The connection's close
   * handler is this class's — the server owns its connections, nobody else sets one — and settles
   * whatever the connection still carried.
   */
  private Set<Exchange> carriedBy(HttpConnection connection) {
    return carried.computeIfAbsent(
        connection,
        c -> {
          Set<Exchange> set = ConcurrentHashMap.newKeySet();
          c.closeHandler(
              v -> {
                Set<Exchange> gone = carried.remove(c);
                if (gone != null) {
                  List.copyOf(gone).forEach(Exchange::settle);
                }
              });
          return set;
        });
  }

  /** How many exchanges are in flight, spliced sockets included. */
  int count() {
    return count.get();
  }

  boolean draining() {
    return draining;
  }

  /**
   * Stop taking new connections and wait for every exchange in flight to end, up to {@code
   * timeout}. Blocking; never called on an event loop.
   *
   * @return whether everything ended in time
   */
  boolean drain(Duration timeout) {
    return drain(timeout, count::get);
  }

  boolean drain(Duration timeout, IntSupplier inFlight) {
    draining = true;
    long started = System.nanoTime();
    long deadline = started + timeout.toNanos();
    int at = inFlight.getAsInt();
    LOG.infof(
        "draining the proxy listener: new connections are refused, %d call(s) in flight are"
            + " served to their end (up to %s)",
        at,
        timeout);
    while (inFlight.getAsInt() > 0 && System.nanoTime() < deadline) {
      try {
        Thread.sleep(POLL_MS);
      } catch (InterruptedException e) {
        Thread.currentThread().interrupt();
        break;
      }
    }
    closed = true;
    int left = inFlight.getAsInt();
    long tookMs = (System.nanoTime() - started) / 1_000_000;
    if (left == 0) {
      LOG.infof("the proxy listener is drained after %d ms", tookMs);
      return true;
    }
    LOG.warnf(
        "the proxy listener drain timed out after %d ms with %d call(s) still in flight; they end"
            + " with the process",
        tookMs,
        left);
    return false;
  }

  /** Serve again after {@link #drain}: for the suites, which drain a listener they keep using. */
  void reopen() {
    draining = false;
    closed = false;
  }
}
