package eu.wohlben.qits.egress.tls;

import eu.wohlben.qits.egress.grants.GrantIndex;
import eu.wohlben.qits.egress.grants.GrantRoute;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.HashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.SortedSet;
import java.util.TreeSet;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.CompletionException;
import java.util.concurrent.CompletionStage;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.TimeUnit;
import org.jboss.logging.Logger;

/**
 * <b>This replica's leaves</b>: one per target host, its key generated here and held in memory only,
 * certified by qits-certificates (epic qits-2524, dossier "Egress TLS interception", "Leaves").
 *
 * <ul>
 *   <li><b>Pre-issue.</b> {@link #want} is told the {@code https://} target hosts of every grant
 *       table this replica adopts ({@link LeafWiring}); each one without a leaf is issued,
 *       asynchronously, at most {@link Settings#concurrency()} at a time.
 *   <li><b>Renewal.</b> {@link #tick} (every few seconds, and after each {@link #want}) issues again
 *       for a wanted host whose leaf passed {@link Settings#renewFraction()} of its life. A failure
 *       retries after a backoff doubling from {@link Settings#backoffMin()} to {@link
 *       Settings#backoffMax()}, and the old leaf is served until it expires.
 *   <li><b>On demand.</b> {@link #issueNow} gives a host's leaf within {@link
 *       Settings#inlineTimeout()}: the held one, the one already being issued, or a new one started
 *       at once, outside the queue.
 * </ul>
 *
 * <p>Nothing is shared between replicas, nothing is written anywhere, and readiness does not wait
 * for a leaf. Every time is read from the {@link Clock}, so a suite drives renewal and backoff.
 *
 * <p>Log lines on {@code eu.wohlben.qits.egress.tls}: INFO {@code egress leaf issued host=<h>
 * serial=<hex> notAfter=<iso>} per issuance, WARN {@code egress leaf failed host=<h> status=<n>
 * reason=<r> retryIn=<d> serving=<serial or ->} per failure. Never a key.
 */
public final class LeafCertificates {

  static final Logger LOG = Logger.getLogger("eu.wohlben.qits.egress.tls");

  /**
   * @param renewFraction the share of a leaf's life after which it is renewed (two thirds)
   * @param concurrency how many pre-issues and renewals run at once
   * @param backoffMin the first retry delay after a failure, doubled per failure
   * @param backoffMax the longest retry delay
   * @param inlineTimeout how long {@link #issueNow} waits
   */
  public record Settings(
      double renewFraction,
      int concurrency,
      Duration backoffMin,
      Duration backoffMax,
      Duration inlineTimeout) {

    public Settings {
      if (!(renewFraction > 0 && renewFraction < 1)) {
        throw new IllegalArgumentException("the renew fraction is between 0 and 1: " + renewFraction);
      }
      if (concurrency < 1) {
        throw new IllegalArgumentException("at least one issuance at a time: " + concurrency);
      }
    }

    /** Two thirds, 4 at a time, 30 s to 10 min, 10 s inline. */
    public static Settings defaults() {
      return new Settings(
          2.0 / 3.0, 4, Duration.ofSeconds(30), Duration.ofMinutes(10), Duration.ofSeconds(10));
    }
  }

  /** A host's failures in a row, and when it is tried again. */
  record Backoff(int failures, Instant retryAt) {}

  private final LeafIssuer issuer;

  private final Clock clock;

  private final Settings settings;

  /** Read without the lock: {@link #leafFor} is on the handshake path. */
  private final Map<String, Leaf> leaves = new ConcurrentHashMap<>();

  // --- guarded by this ---------------------------------------------------------------------------

  private Set<String> wanted = Set.of();

  private final Map<String, CompletableFuture<Leaf>> inFlight = new HashMap<>();

  private final LinkedHashSet<String> queued = new LinkedHashSet<>();

  private final Map<String, Backoff> failures = new HashMap<>();

  public LeafCertificates(LeafIssuer issuer, Clock clock, Settings settings) {
    this.issuer = issuer;
    this.clock = clock;
    this.settings = settings;
  }

  /**
   * The {@code https://} target hosts of a table, lower case, each once: what pre-issue covers. A
   * platform route, a plain-http target and a route that cannot be served are not among them.
   */
  public static SortedSet<String> httpsHosts(GrantIndex.Table table) {
    SortedSet<String> hosts = new TreeSet<>();
    if (table == null) {
      return hosts;
    }
    for (Map<String, GrantRoute> named : table.routes().values()) {
      for (GrantRoute route : named.values()) {
        if (!route.isPlatform() && route.ssl() && route.problem() == null && route.host() != null) {
          hosts.add(normal(route.host()));
        }
      }
    }
    return hosts;
  }

  static String normal(String host) {
    return host.toLowerCase(Locale.ROOT);
  }

  /** The leaf to serve for {@code host} now, if one is valid. */
  public Optional<Leaf> leafFor(String host) {
    if (host == null) {
      return Optional.empty();
    }
    Leaf leaf = leaves.get(normal(host));
    return leaf != null && leaf.validAt(clock.instant()) ? Optional.of(leaf) : Optional.empty();
  }

  /** The hosts pre-issue and renewal currently cover. */
  public synchronized Set<String> wanted() {
    return wanted;
  }

  /**
   * The hosts to hold leaves for from now on — the in-force table's https hosts — and an
   * immediate {@link #tick}. A host no longer wanted keeps its leaf until it expires, but is not
   * renewed.
   */
  public void want(Collection<String> hosts) {
    synchronized (this) {
      SortedSet<String> next = new TreeSet<>();
      hosts.forEach(host -> next.add(normal(host)));
      wanted = Collections.unmodifiableSortedSet(next);
      queued.retainAll(wanted);
      failures.keySet().retainAll(wanted);
    }
    tick();
  }

  /**
   * One pass: drop expired leaves, queue every wanted host without a leaf or past its renewal and
   * not backing off, start as many as the concurrency allows.
   */
  public void tick() {
    List<Start> starts;
    synchronized (this) {
      Instant now = clock.instant();
      leaves.values().removeIf(leaf -> !now.isBefore(leaf.notAfter()));
      for (String host : wanted) {
        if (inFlight.containsKey(host) || queued.contains(host)) {
          continue;
        }
        Leaf leaf = leaves.get(host);
        if (leaf != null && now.isBefore(leaf.renewAt(settings.renewFraction()))) {
          continue;
        }
        Backoff backoff = failures.get(host);
        if (backoff != null && now.isBefore(backoff.retryAt())) {
          continue;
        }
        queued.add(host);
      }
      starts = drain();
    }
    starts.forEach(this::start);
  }

  /**
   * The leaf for {@code host} within the inline timeout: the valid one held, the issuance already
   * running, or one started now ahead of the queue. Fails with a {@link
   * java.util.concurrent.TimeoutException} past the timeout; the issuance itself carries on.
   */
  public CompletionStage<Leaf> issueNow(String host) {
    String name = normal(host);
    CompletableFuture<Leaf> running;
    Start start = null;
    synchronized (this) {
      Leaf held = leaves.get(name);
      if (held != null && held.validAt(clock.instant())) {
        return CompletableFuture.completedFuture(held);
      }
      running = inFlight.get(name);
      if (running == null) {
        queued.remove(name);
        running = new CompletableFuture<>();
        inFlight.put(name, running);
        start = new Start(name, running);
      }
    }
    if (start != null) {
      start(start);
    }
    return running
        .copy()
        .orTimeout(settings.inlineTimeout().toMillis(), TimeUnit.MILLISECONDS);
  }

  /** How long the {@code failures}-th failure in a row waits. */
  Duration backoff(int failures) {
    Duration delay = settings.backoffMin();
    for (int i = 1; i < failures && delay.compareTo(settings.backoffMax()) < 0; i++) {
      delay = delay.multipliedBy(2);
    }
    return delay.compareTo(settings.backoffMax()) > 0 ? settings.backoffMax() : delay;
  }

  /** When {@code host} is tried again, if it is backing off. */
  synchronized Optional<Instant> retryAt(String host) {
    return Optional.ofNullable(failures.get(normal(host))).map(Backoff::retryAt);
  }

  private record Start(String host, CompletableFuture<Leaf> done) {}

  /** Move queued hosts in flight while there is room. Under the lock. */
  private List<Start> drain() {
    List<Start> starts = new ArrayList<>();
    while (inFlight.size() < settings.concurrency() && !queued.isEmpty()) {
      String host = queued.iterator().next();
      queued.remove(host);
      CompletableFuture<Leaf> done = new CompletableFuture<>();
      inFlight.put(host, done);
      starts.add(new Start(host, done));
    }
    return starts;
  }

  /** Ask the issuer. Never under the lock. */
  private void start(Start start) {
    CompletionStage<Leaf> stage;
    try {
      stage = issuer.issue(start.host());
    } catch (RuntimeException e) {
      stage = CompletableFuture.failedFuture(e);
    }
    stage.whenComplete((leaf, error) -> finish(start, leaf, error));
  }

  private void finish(Start start, Leaf leaf, Throwable error) {
    String host = start.host();
    Throwable cause = unwrap(error);
    if (cause == null && leaf == null) {
      cause = new LeafIssueFailed(0, "the issuer answered no leaf");
    }
    List<Start> starts;
    synchronized (this) {
      inFlight.remove(host);
      if (cause == null) {
        leaves.put(host, leaf);
        failures.remove(host);
        LOG.infof(
            "egress leaf issued host=%s serial=%s notAfter=%s", host, leaf.serial(), leaf.notAfter());
      } else {
        Backoff previous = failures.get(host);
        int count = previous == null ? 1 : previous.failures() + 1;
        Duration delay = backoff(count);
        failures.put(host, new Backoff(count, clock.instant().plus(delay)));
        Leaf serving = leaves.get(host);
        LOG.warnf(
            "egress leaf failed host=%s status=%s reason=%s retryIn=%s serving=%s",
            host,
            cause instanceof LeafIssueFailed failed && failed.status() > 0
                ? String.valueOf(failed.status())
                : "-",
            reason(cause),
            delay,
            serving == null ? "-" : serving.serial());
      }
      starts = drain();
    }
    starts.forEach(this::start);
    if (cause == null) {
      start.done().complete(leaf);
    } else {
      start.done().completeExceptionally(cause);
    }
  }

  private static Throwable unwrap(Throwable error) {
    Throwable cause = error;
    while (cause instanceof CompletionException && cause.getCause() != null) {
      cause = cause.getCause();
    }
    return cause;
  }

  /** What a log line may say about a failure: its kind and message, one line, bounded. */
  private static String reason(Throwable cause) {
    String message = cause.getMessage();
    String text =
        cause instanceof LeafIssueFailed
            ? String.valueOf(message)
            : cause.getClass().getSimpleName() + (message == null ? "" : ": " + message);
    text = text.replaceAll("[\\r\\n]+", " ");
    return text.length() > 200 ? text.substring(0, 200) : text;
  }
}
