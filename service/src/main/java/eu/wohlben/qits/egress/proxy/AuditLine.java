package eu.wohlben.qits.egress.proxy;

import java.util.concurrent.atomic.AtomicBoolean;
import java.util.regex.Pattern;
import org.jboss.logging.Logger;

/**
 * <b>The one audit line of one proxied request</b>, on logger {@value #LOGGER} at INFO, written when
 * the response ends or fails — never twice:
 *
 * <pre>
 * egress decision=ALLOW|DENY principal=&lt;p&gt; route=&lt;r&gt; method=&lt;M&gt; target=&lt;host&gt;
 *     path=&lt;path without query&gt; status=&lt;n&gt; durationMs=&lt;n&gt; reason=&lt;reason or -&gt;
 * </pre>
 *
 * <p>(one line; wrapped here). A call inside an intercepted {@code CONNECT} tunnel (qits-2644)
 * ends in {@code tls=intercepted}; the {@code CONNECT} itself in {@code tls=intercepted
 * leafSerial=<hex>}, the leaf the tunnel's handshake is served. A call let through by the
 * passthrough (qits-2654) carries {@code passthrough=true}; a call carried over a {@code GET
 * /egress/api/forward} websocket, {@code via=forward}. It never carries a header value, a query value, a body or a secret:
 * the fields are the principal, the route name, the method, the target host, the path without its
 * query, the status — the upstream's for an allowed call, the gateway's own otherwise — and the
 * reason a call was refused. Every field the caller influences is reduced to a safe alphabet, so a
 * crafted path cannot forge a second key or a second line.
 */
final class AuditLine {

  static final String LOGGER = "eu.wohlben.qits.egress.audit";

  private static final Logger AUDIT = Logger.getLogger(LOGGER);

  /** What may appear in a value unchanged; anything else becomes {@code _}. */
  private static final Pattern UNSAFE = Pattern.compile("[^A-Za-z0-9._~:/@%+,!$&'()*;-]");

  private static final int MAX_VALUE = 512;

  private final long startedNanos = System.nanoTime();

  private final AtomicBoolean written = new AtomicBoolean();

  private volatile String principal = "-";

  private volatile String route = "-";

  private final String method;

  private volatile String target = "-";

  private volatile String path;

  private volatile boolean allowed;

  private volatile String reason = "-";

  private volatile boolean upstreamAnswered;

  private volatile boolean intercepted;

  private volatile String leafSerial;

  private volatile boolean passthrough;

  private volatile boolean forwarded;

  AuditLine(String method, String path) {
    this.method = method;
    this.path = path;
  }

  AuditLine principal(Object principal) {
    this.principal = String.valueOf(principal);
    return this;
  }

  AuditLine route(String route) {
    this.route = route;
    return this;
  }

  AuditLine target(String target, String path) {
    this.target = target;
    this.path = path;
    return this;
  }

  /** The call goes upstream. */
  AuditLine allow() {
    this.allowed = true;
    return this;
  }

  /** The call is refused, for {@code reason}. */
  AuditLine deny(String reason) {
    this.allowed = false;
    this.reason = reason;
    return this;
  }

  /**
   * A reason on a call whatever its decision: an ALLOW that still carries one ({@code websocket},
   * {@code upstream-encoded}).
   */
  AuditLine reason(String reason) {
    this.reason = reason;
    return this;
  }

  /** The call is inside, or is, an intercepted tunnel: {@code tls=intercepted}. */
  AuditLine intercepted() {
    this.intercepted = true;
    return this;
  }

  /** The intercepted {@code CONNECT}'s leaf: {@code leafSerial=<hex>}. */
  AuditLine leafSerial(String serial) {
    this.intercepted = true;
    this.leafSerial = serial;
    return this;
  }

  /** The call goes out by the passthrough, no route: {@code passthrough=true} when allowed. */
  AuditLine passthrough() {
    this.passthrough = true;
    return this;
  }

  /** The call came over a forward's websocket: {@code via=forward}. */
  AuditLine forwarded() {
    this.forwarded = true;
    return this;
  }

  /** Whether the line is written already. */
  boolean written() {
    return written.get();
  }

  /** The upstream answered with a response head. */
  void upstreamAnswered() {
    this.upstreamAnswered = true;
  }

  /** Write the line, once. */
  void write(int status) {
    if (!written.compareAndSet(false, true)) {
      return;
    }
    String why = reason;
    if (allowed && !upstreamAnswered && "-".equals(why)) {
      // The proxy answered itself: no connection, a reset, a TLS failure. Still an ALLOW — the
      // grant held — with the reason the status alone does not give.
      why = "upstream-unreachable";
    }
    AUDIT.info(format(status, why));
  }

  String format(int status, String why) {
    long durationMs = (System.nanoTime() - startedNanos) / 1_000_000;
    return "egress decision="
        + (allowed ? "ALLOW" : "DENY")
        + " principal="
        + clean(principal)
        + " route="
        + clean(route)
        + " method="
        + clean(method)
        + " target="
        + clean(target)
        + " path="
        + clean(path)
        + " status="
        + status
        + " durationMs="
        + durationMs
        + " reason="
        + clean(why)
        + (intercepted ? " tls=intercepted" : "")
        + (leafSerial != null ? " leafSerial=" + clean(leafSerial) : "")
        + (passthrough && allowed ? " passthrough=true" : "")
        + (forwarded ? " via=forward" : "");
  }

  static String clean(String value) {
    if (value == null || value.isEmpty()) {
      return "-";
    }
    String cut = value.length() > MAX_VALUE ? value.substring(0, MAX_VALUE) : value;
    return UNSAFE.matcher(cut).replaceAll("_");
  }
}
