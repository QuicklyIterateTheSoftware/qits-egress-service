package eu.wohlben.qits.egress.proxy;

import io.opentelemetry.api.trace.Span;
import io.opentelemetry.api.trace.SpanContext;
import io.vertx.core.http.HttpHeaders;
import io.vertx.core.http.HttpServerRequest;
import io.vertx.core.net.SocketAddress;
import java.util.Locale;

/**
 * Who is holding an upstream connection: the inbound exchange a pooled connection is carrying right
 * now, read off the request before the connection is asked for. Copied from qits-edge, where a full
 * pool used to be a bare number and turned out to be dozens of agents' event streams; a lease names
 * the holder, and {@link UpstreamPools}' WARN quotes the oldest.
 *
 * <p><b>Everything here is diagnostics, and nothing here is a credential.</b> The path is read
 * WITHOUT its query string, because a query is where a token in a URL would be; no header beyond
 * {@code User-Agent} is kept. On the gateway the path is the caller's own form ({@code
 * /<route>/<rest>}), an absolute-form target's path, or {@code -} for a tunnel.
 *
 * @param method the inbound method, e.g. {@code GET}
 * @param path the inbound path, without its query string
 * @param client the first {@code X-Forwarded-For} entry, else the peer's host; null when neither
 * @param userAgent the inbound {@code User-Agent}, or null
 * @param traceId the trace this exchange belongs to, or null
 */
record UpstreamLease(String method, String path, String client, String userAgent, String traceId) {

  /**
   * The lease for one inbound request. Never throws: it runs inside the origin provider, and a
   * request must not fail over bookkeeping — a part that cannot be read is null instead.
   */
  static UpstreamLease of(HttpServerRequest request) {
    try {
      return new UpstreamLease(
          request.method() == null ? null : request.method().name(),
          request.path(),
          client(request),
          request.getHeader(HttpHeaders.USER_AGENT),
          traceId(request));
    } catch (RuntimeException unreadable) {
      return new UpstreamLease(null, null, null, null, null);
    }
  }

  /** The first {@code X-Forwarded-For} hop, else the socket's peer. Diagnostics only. */
  static String client(HttpServerRequest request) {
    String forwarded = request.getHeader("X-Forwarded-For");
    if (forwarded != null) {
      int comma = forwarded.indexOf(',');
      String first = (comma < 0 ? forwarded : forwarded.substring(0, comma)).strip();
      if (!first.isEmpty()) {
        return first;
      }
    }
    SocketAddress peer = request.remoteAddress();
    return peer == null ? null : peer.host();
  }

  /**
   * The trace id of this exchange: the current span's when there is a valid one, else the inbound
   * {@code traceparent}'s. The proxy listener is a plain Vert.x server, so no server span is
   * attached to the request the way Quarkus HTTP attaches one; the header is the usual source.
   */
  static String traceId(HttpServerRequest request) {
    try {
      SpanContext current = Span.current().getSpanContext();
      if (current.isValid()) {
        return current.getTraceId();
      }
    } catch (RuntimeException | LinkageError noTracing) {
      // Diagnostics only; fall through to the header.
    }
    return traceparentTraceId(request.getHeader("traceparent"));
  }

  /**
   * The trace id of a W3C {@code traceparent}, {@code 00-<32 hex>-<16 hex>-<2 hex>}, or null for
   * anything that is not one — including the all-zero id the spec calls invalid.
   */
  static String traceparentTraceId(String traceparent) {
    if (traceparent == null) {
      return null;
    }
    String[] parts = traceparent.strip().toLowerCase(Locale.ROOT).split("-");
    if (parts.length < 4 || parts[0].length() != 2 || parts[1].length() != 32) {
      return null;
    }
    String traceId = parts[1];
    for (int i = 0; i < traceId.length(); i++) {
      char c = traceId.charAt(i);
      if (!(c >= '0' && c <= '9' || c >= 'a' && c <= 'f')) {
        return null;
      }
    }
    return traceId.equals("0".repeat(32)) ? null : traceId;
  }
}
