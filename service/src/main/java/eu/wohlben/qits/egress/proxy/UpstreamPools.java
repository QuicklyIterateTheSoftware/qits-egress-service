package eu.wohlben.qits.egress.proxy;

import io.vertx.core.http.HttpClientRequest;
import io.vertx.core.http.HttpConnection;
import io.vertx.core.net.SocketAddress;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.TimeUnit;
import java.util.function.LongSupplier;
import org.jboss.logging.Logger;

/**
 * One proxy client's pool, seen from outside: how many connections it holds open to each origin,
 * which exchange each leased connection is carrying, and a WARN for an origin whose pool is under
 * pressure. Copied from qits-edge, without its {@code /upstream-pools} door and its stream sweep:
 * the gateway closes no stream early, and has no management door on the proxy listener.
 *
 * <p><b>There are two of these, one per client.</b> {@link EgressProxy} proxies long-lived streams
 * — an SSE GET, a WebSocket — through a client of their own ({@link #STREAM}), because each one
 * holds a pooled HTTP/1.1 connection for its whole life, and a pool shared with everything else
 * fills up with them until every ordinary call to that origin queues behind them for its thirty
 * seconds and fails (qits-edge's outage, 2026). A stream competes only with other streams.
 *
 * <p><b>Counted from the connection's own life</b>: up in the client's connect handler, down when
 * the Netty CHANNEL under it closes. A tunnel (a WebSocket's {@code 101}) keeps its slot until it
 * closes, so {@code open} is the pool's real occupancy.
 *
 * <p><b>A lease</b> is the {@link UpstreamLease} of the exchange a connection is carrying, from the
 * moment the pool granted it until that exchange is over — the upstream response's end, the
 * response never coming, or the channel closing, whichever is first. The first two remove the lease
 * only if it is still theirs ({@code remove(key, value)}).
 *
 * <p><b>The WARN is about pressure</b>: in the interval since the previous {@link #check}, an origin
 * spent longer than {@link #AT_MAX_WARN_MS} at max, or an acquisition waited longer than {@link
 * #SLOW_ACQUISITION_MS}. The line names the five oldest leases — what the pool is full OF.
 */
final class UpstreamPools {

  private static final Logger LOG = Logger.getLogger(UpstreamPools.class);

  /** The pool ordinary requests are proxied through: everything that is not a stream. */
  static final String ORDINARY = "ordinary";

  /** The pool long-lived streams are proxied through — see {@link EgressProxy#isStream}. */
  static final String STREAM = "stream";

  /** How often {@link #check} runs, and therefore what "the interval" is. */
  static final long CHECK_INTERVAL_MS = 60_000;

  /** How long in one interval an origin may sit at max before it is reported: half of it. */
  static final long AT_MAX_WARN_MS = 30_000;

  /** An acquisition that waited longer than this is reported. */
  static final long SLOW_ACQUISITION_MS = 5_000;

  /** How many of an origin's leases a WARN names, oldest first. */
  static final int WARN_OLDEST_LEASES = 5;

  private final String pool;

  private final int max;

  private final LongSupplier nanoTime;

  private final Map<UpstreamOrigin, Origin> origins = new ConcurrentHashMap<>();

  /** One entry per leased connection, keyed by {@link #key}. */
  private final Map<Object, Held> held = new ConcurrentHashMap<>();

  private long lastCheckNanos;

  /** One origin's count and the interval's measurements, synchronized on the origin. */
  private static final class Origin {

    private int open;

    private long atMaxSince = -1;

    private long atMaxNanos;

    private long longestWaitNanos;

    private int slowWaits;

    synchronized void opened(int max, long now) {
      open++;
      if (open >= max && atMaxSince < 0) {
        atMaxSince = now;
      }
    }

    synchronized void closed(int max, long now) {
      if (open > 0) {
        open--;
      }
      if (open < max && atMaxSince >= 0) {
        atMaxNanos += now - atMaxSince;
        atMaxSince = -1;
      }
    }

    synchronized void waited(long nanos) {
      longestWaitNanos = Math.max(longestWaitNanos, nanos);
      if (nanos > TimeUnit.MILLISECONDS.toNanos(SLOW_ACQUISITION_MS)) {
        slowWaits++;
      }
    }

    synchronized int open() {
      return open;
    }

    synchronized Interval drain(long now) {
      long atMax = atMaxNanos + (atMaxSince >= 0 ? now - atMaxSince : 0);
      Interval interval = new Interval(open, atMax, longestWaitNanos, slowWaits);
      atMaxNanos = 0;
      if (atMaxSince >= 0) {
        atMaxSince = now;
      }
      longestWaitNanos = 0;
      slowWaits = 0;
      return interval;
    }
  }

  private record Interval(int open, long atMaxNanos, long longestWaitNanos, int slowWaits) {}

  /** One leased connection: whose origin, which exchange, since when. */
  record Held(UpstreamOrigin origin, UpstreamLease lease, long sinceNanos) {}

  /**
   * @param pool which client this counts — {@link #ORDINARY} or {@link #STREAM}
   * @param max the client's configured pool size per origin — what "full" means
   */
  UpstreamPools(String pool, int max) {
    this(pool, max, System::nanoTime);
  }

  UpstreamPools(String pool, int max, LongSupplier nanoTime) {
    this.pool = pool;
    this.max = max;
    this.nanoTime = nanoTime;
    this.lastCheckNanos = nanoTime.getAsLong();
  }

  String pool() {
    return pool;
  }

  /**
   * The proxy client's connect handler: set the socket's keepalive timers, count the connection
   * against its origin, and uncount it — dropping any lease it still carries — when its channel
   * closes. Never throws.
   */
  void connected(HttpConnection connection) {
    UpstreamKeepAlive.apply(connection);
    UpstreamOrigin origin = origin(connection.remoteAddress());
    if (origin == null) {
      return;
    }
    opened(origin);
    try {
      io.netty.channel.Channel key = UpstreamChannel.of(connection);
      key.closeFuture()
          .addListener(
              closed -> {
                closed(origin);
                held.remove(key);
              });
    } catch (RuntimeException unreachable) {
      connection.closeHandler(
          closed -> {
            closed(origin);
            held.remove(connection);
          });
    }
  }

  /** The lease key: the connection's Netty channel, or the connection when the cast fails. */
  static Object key(HttpConnection connection) {
    try {
      return UpstreamChannel.of(connection);
    } catch (RuntimeException unreachable) {
      return connection;
    }
  }

  /** The origin a connection was dialled as, or null for an address that is not one. */
  static UpstreamOrigin origin(SocketAddress remote) {
    if (remote == null || remote.host() == null || remote.host().isBlank()) {
      return null;
    }
    try {
      return new UpstreamOrigin(remote.host(), remote.port());
    } catch (IllegalArgumentException notAnOrigin) {
      return null;
    }
  }

  void opened(UpstreamOrigin origin) {
    origins.computeIfAbsent(origin, ignored -> new Origin()).opened(max, nanoTime.getAsLong());
  }

  void closed(UpstreamOrigin origin) {
    Origin counted = origins.get(origin);
    if (counted != null) {
      counted.closed(max, nanoTime.getAsLong());
    }
  }

  /** The moment an acquisition starts. */
  long acquiring() {
    return nanoTime.getAsLong();
  }

  /**
   * An origin request was granted a connection: time the wait, and lease the connection to the
   * exchange until it is over. Never throws.
   *
   * @param untilClose true for a request that becomes a tunnel — a WebSocket handshake — whose
   *     lease ends only when its channel closes
   */
  void granted(
      UpstreamOrigin dialled,
      long since,
      HttpClientRequest request,
      UpstreamLease lease,
      boolean untilClose) {
    try {
      waited(dialled, nanoTime.getAsLong() - since);
      HttpConnection connection = request.connection();
      if (connection == null) {
        return;
      }
      UpstreamOrigin origin = origin(connection.remoteAddress());
      Object key = key(connection);
      Held leased = lease(key, origin == null ? dialled : origin, lease);
      if (key instanceof io.netty.channel.Channel channel && !channel.isOpen()) {
        release(key, leased);
        return;
      }
      if (untilClose) {
        return;
      }
      request
          .response()
          .onComplete(
              answered -> {
                if (answered.failed()) {
                  release(key, leased);
                } else {
                  answered.result().end().onComplete(ended -> release(key, leased));
                }
              });
    } catch (RuntimeException failure) {
      LOG.errorf(failure, "could not record the lease on a connection to %s", dialled);
    }
  }

  /** An origin request was refused a connection — a full queue, a timeout, a refused connect. */
  void failed(UpstreamOrigin dialled, long since) {
    try {
      waited(dialled, nanoTime.getAsLong() - since);
    } catch (RuntimeException failure) {
      LOG.errorf(failure, "could not record a failed acquisition to %s", dialled);
    }
  }

  void waited(UpstreamOrigin dialled, long nanos) {
    origins.computeIfAbsent(dialled, ignored -> new Origin()).waited(nanos);
  }

  Held lease(Object key, UpstreamOrigin origin, UpstreamLease lease) {
    Held leased = new Held(origin, lease, nanoTime.getAsLong());
    held.put(key, leased);
    return leased;
  }

  void release(Object key, Held leased) {
    held.remove(key, leased);
  }

  /** Every lease now held: what a leak test has to see. */
  List<UpstreamLease> leases() {
    return held.values().stream().map(Held::lease).toList();
  }

  /** Every origin with at least one open connection, and how many. */
  Map<UpstreamOrigin, Integer> open() {
    Map<UpstreamOrigin, Integer> open = new LinkedHashMap<>();
    origins.forEach(
        (origin, counted) -> {
          int now = counted.open();
          if (now > 0) {
            open.put(origin, now);
          }
        });
    return open;
  }

  private List<Held> heldBy(UpstreamOrigin origin) {
    return held.values().stream()
        .filter(leased -> leased.origin().equals(origin))
        .sorted(Comparator.comparingLong(Held::sinceNanos))
        .toList();
  }

  /**
   * The periodic check: one WARN per origin under pressure in the interval since the previous
   * check. Every interval measurement is reset here.
   *
   * @return the origins reported
   */
  synchronized List<UpstreamOrigin> check() {
    long now = nanoTime.getAsLong();
    long intervalNanos = now - lastCheckNanos;
    lastCheckNanos = now;
    List<UpstreamOrigin> pressed = new ArrayList<>();
    origins.forEach(
        (origin, counted) -> {
          Interval interval = counted.drain(now);
          boolean longAtMax = interval.atMaxNanos() > TimeUnit.MILLISECONDS.toNanos(AT_MAX_WARN_MS);
          if (!longAtMax && interval.slowWaits() == 0) {
            return;
          }
          pressed.add(origin);
          LOG.warnf(
              "the %s upstream pool to %s is under pressure: %d/%d open, %s of the last %s at max,"
                  + " longest wait for a connection %s, %d waits over %d s (a request waits up to"
                  + " %d ms and then fails); oldest held: %s",
              pool,
              origin,
              interval.open(),
              max,
              seconds(interval.atMaxNanos()),
              seconds(intervalNanos),
              seconds(interval.longestWaitNanos()),
              interval.slowWaits(),
              SLOW_ACQUISITION_MS / 1000,
              ProxyClients.ACQUIRE_TIMEOUT_MS,
              oldest(origin, now));
        });
    return pressed;
  }

  /** The five oldest leases of one origin, as a WARN quotes them. */
  String oldest(UpstreamOrigin origin, long now) {
    List<Held> leases = heldBy(origin);
    if (leases.isEmpty()) {
      return "none";
    }
    List<String> named = new ArrayList<>();
    for (Held leased : leases.subList(0, Math.min(WARN_OLDEST_LEASES, leases.size()))) {
      UpstreamLease lease = leased.lease();
      named.add(
          lease.method()
              + " "
              + AuditLine.clean(lease.path())
              + " "
              + seconds(now - leased.sinceNanos())
              + " client="
              + lease.client()
              + " trace="
              + lease.traceId());
    }
    return String.join("; ", named)
        + (leases.size() > WARN_OLDEST_LEASES
            ? "; and " + (leases.size() - WARN_OLDEST_LEASES) + " more"
            : "");
  }

  private static String seconds(long nanos) {
    return String.format(Locale.ROOT, "%.1f s", nanos / 1e9);
  }
}
