package eu.wohlben.qits.egress.proxy;

import eu.wohlben.qits.servicemock.idp.MockIdp;
import io.vertx.core.MultiMap;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.List;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.function.Predicate;
import java.util.logging.Handler;
import java.util.logging.LogRecord;
import java.util.logging.Logger;

/**
 * The forward and passthrough suites' wire helpers (qits-2654): a response head and body read off a
 * raw stream, the callers' tokens, and the audit lines.
 */
final class ProxyWire {

  private ProxyWire() {}

  /** A response head: the status, its reason phrase and the header lines. */
  record Head(int status, String reason, MultiMap headers) {}

  static Head head(InputStream in) throws IOException {
    ByteArrayOutputStream bytes = new ByteArrayOutputStream();
    int matched = 0;
    while (matched < 4) {
      int b = in.read();
      if (b < 0) {
        throw new IOException("closed before the head ended: " + bytes);
      }
      bytes.write(b);
      matched = (b == "\r\n\r\n".charAt(matched)) ? matched + 1 : (b == '\r' ? 1 : 0);
    }
    String[] lines = bytes.toString(StandardCharsets.ISO_8859_1).split("\r\n");
    MultiMap headers = MultiMap.caseInsensitiveMultiMap();
    for (int i = 1; i < lines.length; i++) {
      int colon = lines[i].indexOf(':');
      if (colon > 0) {
        headers.add(lines[i].substring(0, colon).trim(), lines[i].substring(colon + 1).trim());
      }
    }
    String[] status = lines[0].split(" ", 3);
    return new Head(Integer.parseInt(status[1]), status.length > 2 ? status[2] : "", headers);
  }

  /** The body: as long as {@code Content-Length} says, else chunked, else none. */
  static String body(InputStream in, Head head) throws IOException {
    String length = head.headers().get("Content-Length");
    if (length != null) {
      return new String(in.readNBytes(Integer.parseInt(length)), StandardCharsets.UTF_8);
    }
    if (!"chunked".equalsIgnoreCase(head.headers().get("Transfer-Encoding"))) {
      return "";
    }
    StringBuilder body = new StringBuilder();
    while (true) {
      StringBuilder size = new StringBuilder();
      int b;
      while ((b = in.read()) != '\n') {
        if (b != '\r') {
          size.append((char) b);
        }
      }
      int n = Integer.parseInt(size.toString().trim(), 16);
      if (n == 0) {
        in.readNBytes(2);
        return body.toString();
      }
      body.append(new String(in.readNBytes(n), StandardCharsets.UTF_8));
      in.readNBytes(2);
    }
  }

  static String basic(String token) {
    return "Basic "
        + Base64.getEncoder().encodeToString(("anyone:" + token).getBytes(StandardCharsets.UTF_8));
  }

  /** A platform service's own client: {@code application:qits-edge}. */
  static String applicationToken() {
    return MockIdp.ensureStarted()
        .token()
        .subject("dev-qits-edge")
        .audience("qits-platform")
        .groups("clients/dev-qits-edge", "qits:system")
        .mint();
  }

  /** A workspace container's token: {@code project:qits}. */
  static String projectToken() {
    return MockIdp.ensureStarted()
        .token()
        .subject("tok-workspace-qits")
        .audience("qits-platform")
        .groups("qits:agent")
        .claim("project", "qits")
        .mint();
  }

  /** A launch's per-agent token: {@code agent:developer} of project {@code qits}. */
  static String agentToken() {
    return MockIdp.ensureStarted()
        .token()
        .subject("tok-agent-qits-developer")
        .audience("qits-platform")
        .groups("qits:agent")
        .claim("agent", "developer")
        .claim("project", "qits")
        .mint();
  }

  /** The audit lines, captured while installed. */
  static final class Audit extends Handler implements AutoCloseable {

    final List<String> lines = new CopyOnWriteArrayList<>();

    Audit() {
      Logger.getLogger(AuditLine.LOGGER).addHandler(this);
    }

    @Override
    public void publish(LogRecord record) {
      lines.add(record.getMessage());
    }

    @Override
    public void flush() {}

    @Override
    public void close() {
      Logger.getLogger(AuditLine.LOGGER).removeHandler(this);
    }

    /** The first line matching, waited for up to 5 s, and taken out. */
    String await(Predicate<String> matching) throws InterruptedException {
      long deadline = System.currentTimeMillis() + 5_000;
      while (System.currentTimeMillis() < deadline) {
        for (String line : lines) {
          if (matching.test(line)) {
            lines.remove(line);
            return line;
          }
        }
        Thread.sleep(20);
      }
      throw new AssertionError("no audit line matched; lines: " + lines);
    }
  }
}
