package eu.wohlben.qits.egress.proxy;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.fasterxml.jackson.databind.ObjectMapper;
import eu.wohlben.qits.egress.api.GrantTableWire;
import eu.wohlben.qits.egress.grants.GrantIndex;
import eu.wohlben.qits.egress.store.GrantTableStore;
import eu.wohlben.qits.servicemock.idp.MockIdp;
import io.quarkus.test.junit.QuarkusTest;
import io.vertx.core.MultiMap;
import io.vertx.core.Vertx;
import io.vertx.core.http.HttpServer;
import io.vertx.core.json.JsonObject;
import io.vertx.core.net.NetServer;
import jakarta.inject.Inject;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.Authenticator;
import java.net.InetSocketAddress;
import java.net.PasswordAuthentication;
import java.net.ProxySelector;
import java.net.Socket;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Base64;
import java.util.List;
import java.util.concurrent.BlockingQueue;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.LinkedBlockingQueue;
import java.util.concurrent.TimeUnit;
import java.util.logging.Handler;
import java.util.logging.LogRecord;
import java.util.logging.Logger;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Assumptions;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

/**
 * <b>The HTTPS_PROXY forms</b> (qits-2622) through the real listener: {@code Proxy-Authorization},
 * absolute-form requests matched to a route by origin and base path, and {@code CONNECT} tunnels to
 * a local TCP echo (a plain {@code http://} route target, allowed by the suite's test flag). The
 * clients are a raw socket — exact bytes, the CONNECT handshake — the JDK's own proxy support, and
 * {@code curl -x} where the image has curl.
 */
@QuarkusTest
class EgressProxyFormsTest {

  static final String SECRET = "suite-upstream-secret-value";

  static final String EDGE = "dev-qits-edge";

  record Received(String uri, MultiMap headers) {}

  static Vertx upstreamVertx;

  static HttpServer upstream;

  static NetServer echo;

  static final BlockingQueue<Received> RECEIVED = new LinkedBlockingQueue<>();

  @Inject EgressProxy proxy;

  @Inject GrantTableStore store;

  @Inject GrantIndex index;

  @Inject ObjectMapper json;

  final List<String> audit = new CopyOnWriteArrayList<>();

  final Handler capture =
      new Handler() {
        @Override
        public void publish(LogRecord record) {
          audit.add(record.getMessage());
        }

        @Override
        public void flush() {}

        @Override
        public void close() {}
      };

  @BeforeAll
  static void startTheUpstreams() throws Exception {
    upstreamVertx = Vertx.vertx();
    upstream =
        upstreamVertx
            .createHttpServer()
            .requestHandler(
                request -> {
                  MultiMap headers = MultiMap.caseInsensitiveMultiMap();
                  headers.addAll(request.headers());
                  RECEIVED.add(new Received(request.uri(), headers));
                  request.response().putHeader("Content-Type", "text/plain").end("upstream answered");
                })
            .listen(0, "127.0.0.1")
            .toCompletionStage()
            .toCompletableFuture()
            .get(10, TimeUnit.SECONDS);
    echo =
        upstreamVertx
            .createNetServer()
            .connectHandler(socket -> socket.handler(socket::write))
            .listen(0, "127.0.0.1")
            .toCompletionStage()
            .toCompletableFuture()
            .get(10, TimeUnit.SECONDS);
  }

  @AfterAll
  static void stopTheUpstreams() throws Exception {
    upstreamVertx.close().toCompletionStage().toCompletableFuture().get(10, TimeUnit.SECONDS);
  }

  @BeforeEach
  void grant() throws Exception {
    RECEIVED.clear();
    Logger.getLogger(AuditLine.LOGGER).addHandler(capture);
    String target = "http://127.0.0.1:" + upstream.actualPort();
    GrantTableWire.GrantTable table =
        new GrantTableWire.GrantTable(
            System.currentTimeMillis(),
            List.of(
                route("suite", target + "/base", "SUITE_UPSTREAM", "header:X-Api-Key", "GET", "POST"),
                route("deeper", target + "/base/deeper", "SUITE_UPSTREAM", "bearer", "GET"),
                route("tunnel", "http://127.0.0.1:" + echo.actualPort(), null, null, "CONNECT")),
            List.of());
    store.clear();
    store.store(table.version(), json.writeValueAsString(table), "application:qits-deployments");
    index.refresh();
  }

  @AfterEach
  void stopListening() {
    Logger.getLogger(AuditLine.LOGGER).removeHandler(capture);
  }

  private static GrantTableWire.Route route(
      String name, String target, String secret, String inject, String... methods) {
    return new GrantTableWire.Route(
        "qits-edge", "dev", "2026.1201.101010", name, target, secret, inject, List.of(methods));
  }

  private static String token() {
    return MockIdp.ensureStarted()
        .token()
        .subject(EDGE)
        .audience("qits-platform")
        .groups("clients/" + EDGE, "qits:system")
        .mint();
  }

  private static String basic(String token) {
    return "Basic "
        + Base64.getEncoder().encodeToString(("anyone:" + token).getBytes(StandardCharsets.UTF_8));
  }

  private String auditLine() throws InterruptedException {
    long deadline = System.currentTimeMillis() + 5_000;
    while (audit.isEmpty() && System.currentTimeMillis() < deadline) {
      Thread.sleep(20);
    }
    assertFalse(audit.isEmpty(), "an audit line was written");
    return audit.remove(0);
  }

  // --- a raw HTTP/1.1 exchange -------------------------------------------------------------------

  /** A response head read off a socket: the status and the header lines. */
  record Head(int status, MultiMap headers) {}

  private static Head head(InputStream in) throws IOException {
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
    return new Head(Integer.parseInt(lines[0].split(" ")[1]), headers);
  }

  private static String body(InputStream in, Head head) throws IOException {
    String length = head.headers().get("Content-Length");
    if (length != null) {
      return new String(in.readNBytes(Integer.parseInt(length)), StandardCharsets.UTF_8);
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

  /** One request through a fresh socket; the head and the body. */
  private record Answer(Head head, String body) {}

  private Answer raw(String requestHead) throws IOException {
    try (Socket socket = new Socket("127.0.0.1", proxy.port())) {
      socket.setSoTimeout(10_000);
      OutputStream out = socket.getOutputStream();
      out.write(requestHead.getBytes(StandardCharsets.ISO_8859_1));
      out.flush();
      InputStream in = socket.getInputStream();
      Head head = head(in);
      return new Answer(head, body(in, head));
    }
  }

  // --- Proxy-Authorization -----------------------------------------------------------------------

  @Test
  void noProxyCredentialIs407WithABasicChallenge() throws Exception {
    String url = "http://127.0.0.1:" + upstream.actualPort() + "/base/v1";
    Answer answer = raw("GET " + url + " HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n");
    assertEquals(407, answer.head().status());
    assertEquals("Basic realm=\"qits-egress\"", answer.head().headers().get("Proxy-Authenticate"));
    assertNull(answer.head().headers().get("WWW-Authenticate"));
    assertNotNull(new JsonObject(answer.body()).getString("error"));
    assertTrue(auditLine().endsWith(" reason=no-credentials"));

    // An Authorization meant for the target is no proxy credential.
    answer =
        raw(
            "GET " + url + " HTTP/1.1\r\nHost: 127.0.0.1\r\nAuthorization: Bearer " + token()
                + "\r\nConnection: close\r\n\r\n");
    assertEquals(407, answer.head().status());
    auditLine();

    answer =
        raw(
            "GET " + url + " HTTP/1.1\r\nHost: 127.0.0.1\r\nProxy-Authorization: " + basic("not-a-jwt")
                + "\r\nConnection: close\r\n\r\n");
    assertEquals(407, answer.head().status());
    assertTrue(auditLine().endsWith(" reason=bad-credentials"));

    answer =
        raw(
            "CONNECT 127.0.0.1:" + echo.actualPort() + " HTTP/1.1\r\nHost: 127.0.0.1:"
                + echo.actualPort() + "\r\n\r\n");
    assertEquals(407, answer.head().status());
    assertEquals("Basic realm=\"qits-egress\"", answer.head().headers().get("Proxy-Authenticate"));
    String line = auditLine();
    assertTrue(line.contains(" method=CONNECT "), line);
    assertTrue(RECEIVED.isEmpty());
  }

  // --- absolute-form -----------------------------------------------------------------------------

  @Test
  void anAbsoluteFormRequestGetsTheSecretInjected() throws Exception {
    String token = token();
    Answer answer =
        raw(
            "GET http://127.0.0.1:" + upstream.actualPort() + "/base/v1/zones?name=q HTTP/1.1\r\n"
                + "Host: 127.0.0.1:" + upstream.actualPort() + "\r\n"
                + "Proxy-Authorization: " + basic(token) + "\r\n"
                + "Authorization: Bearer caller-own-target-credential\r\n"
                + "Proxy-Connection: keep-alive\r\n"
                + "Connection: close\r\n\r\n");
    assertEquals(200, answer.head().status(), answer.body());
    assertEquals("upstream answered", answer.body());
    Received received = RECEIVED.poll(5, TimeUnit.SECONDS);
    assertNotNull(received);
    assertEquals("/base/v1/zones?name=q", received.uri());
    assertEquals(SECRET, received.headers().get("X-Api-Key"));
    assertNull(received.headers().get("Authorization"), "the caller's credentials stay behind");
    assertNull(received.headers().get("Proxy-Authorization"));
    assertNull(received.headers().get("Proxy-Connection"));
    String line = auditLine();
    assertTrue(
        line.startsWith(
            "egress decision=ALLOW principal=application:qits-edge route=suite method=GET"
                + " target=127.0.0.1 path=/base/v1/zones status=200"),
        line);
    assertFalse(line.contains(token));
  }

  @Test
  void theLongestBasePathPicksTheRouteAndABearerProxyCredentialWorks() throws Exception {
    Answer answer =
        raw(
            "GET http://127.0.0.1:" + upstream.actualPort() + "/base/deeper/x HTTP/1.1\r\n"
                + "Host: 127.0.0.1\r\nProxy-Authorization: Bearer " + token()
                + "\r\nConnection: close\r\n\r\n");
    assertEquals(200, answer.head().status(), answer.body());
    assertEquals("Bearer " + SECRET, RECEIVED.poll(5, TimeUnit.SECONDS).headers().get("Authorization"));
    assertTrue(auditLine().contains(" route=deeper method=GET"));
  }

  @Test
  void anAbsoluteFormRequestNoRouteCoversIsForbidden() throws Exception {
    Answer answer =
        raw(
            "GET http://127.0.0.1:1/base/v1 HTTP/1.1\r\nHost: 127.0.0.1:1\r\nProxy-Authorization: "
                + basic(token()) + "\r\nConnection: close\r\n\r\n");
    assertEquals(403, answer.head().status());
    JsonObject body = new JsonObject(answer.body());
    assertEquals("no grant", body.getString("error"));
    assertEquals("http://127.0.0.1:1", body.getString("target"));
    assertTrue(auditLine().endsWith(" reason=no-grant"));

    answer =
        raw(
            "DELETE http://127.0.0.1:" + upstream.actualPort() + "/base/v1 HTTP/1.1\r\nHost: x\r\n"
                + "Proxy-Authorization: " + basic(token()) + "\r\nConnection: close\r\n\r\n");
    assertEquals(403, answer.head().status());
    assertEquals("suite", new JsonObject(answer.body()).getString("route"));
    assertTrue(auditLine().endsWith(" reason=method-not-granted"));
    assertTrue(RECEIVED.isEmpty());
  }

  @Test
  void theJdksOwnProxySupportGetsTheSecretInjected() throws Exception {
    String token = token();
    HttpClient client =
        HttpClient.newBuilder()
            .version(HttpClient.Version.HTTP_1_1)
            .proxy(ProxySelector.of(new InetSocketAddress("127.0.0.1", proxy.port())))
            .authenticator(
                new Authenticator() {
                  @Override
                  protected PasswordAuthentication getPasswordAuthentication() {
                    return getRequestorType() == RequestorType.PROXY
                        ? new PasswordAuthentication("anyone", token.toCharArray())
                        : null;
                  }
                })
            .build();
    HttpResponse<String> answer =
        client.send(
            HttpRequest.newBuilder(
                    URI.create("http://127.0.0.1:" + upstream.actualPort() + "/base/jdk?via=proxy"))
                .build(),
            HttpResponse.BodyHandlers.ofString());
    assertEquals(200, answer.statusCode(), answer.body());
    assertEquals("upstream answered", answer.body());
    Received received = RECEIVED.poll(5, TimeUnit.SECONDS);
    assertNotNull(received);
    assertEquals("/base/jdk?via=proxy", received.uri());
    assertEquals(SECRET, received.headers().get("X-Api-Key"));
    assertNull(received.headers().get("Proxy-Authorization"));
    // The JDK asks first without a credential, is answered 407, and asks again with Basic.
    assertTrue(auditLine().endsWith(" reason=no-credentials"));
    assertTrue(auditLine().contains("decision=ALLOW principal=application:qits-edge route=suite"));
  }

  @Test
  void curlThroughTheProxyGetsTheSecretInjected() throws Exception {
    Path curl = Path.of("/usr/bin/curl");
    Assumptions.assumeTrue(Files.isExecutable(curl), "no curl in this image");
    String token = token();
    Process run =
        new ProcessBuilder(
                curl.toString(),
                "-sS",
                "--max-time",
                "20",
                "-x",
                "http://127.0.0.1:" + proxy.port(),
                "-U",
                "anyone:" + token,
                "http://127.0.0.1:" + upstream.actualPort() + "/base/curl")
            .redirectErrorStream(true)
            .start();
    String out = new String(run.getInputStream().readAllBytes(), StandardCharsets.UTF_8);
    assertTrue(run.waitFor(30, TimeUnit.SECONDS));
    assertEquals(0, run.exitValue(), out);
    assertEquals("upstream answered", out);
    Received received = RECEIVED.poll(5, TimeUnit.SECONDS);
    assertNotNull(received);
    assertEquals("/base/curl", received.uri());
    assertEquals(SECRET, received.headers().get("X-Api-Key"));
    assertNull(received.headers().get("Proxy-Authorization"));
    assertTrue(auditLine().contains("decision=ALLOW principal=application:qits-edge route=suite"));
  }

  // --- CONNECT -----------------------------------------------------------------------------------

  @Test
  void aConnectToAGrantedTunnelSplicesTheBytes() throws Exception {
    try (Socket socket = new Socket("127.0.0.1", proxy.port())) {
      socket.setSoTimeout(10_000);
      OutputStream out = socket.getOutputStream();
      out.write(
          ("CONNECT 127.0.0.1:" + echo.actualPort() + " HTTP/1.1\r\nHost: 127.0.0.1:"
                  + echo.actualPort() + "\r\nProxy-Authorization: " + basic(token()) + "\r\n\r\n")
              .getBytes(StandardCharsets.ISO_8859_1));
      out.flush();
      InputStream in = socket.getInputStream();
      Head head = head(in);
      assertEquals(200, head.status());
      byte[] ping = "ping through the tunnel\n".getBytes(StandardCharsets.UTF_8);
      out.write(ping);
      out.flush();
      assertEquals(
          "ping through the tunnel\n",
          new String(in.readNBytes(ping.length), StandardCharsets.UTF_8),
          "the echo answered through the tunnel, byte for byte");
      assertEquals(1, proxy.inFlight(), "an open tunnel is a call in flight");
    }
    String line = auditLine();
    assertTrue(
        line.startsWith(
            "egress decision=ALLOW principal=application:qits-edge route=tunnel method=CONNECT"
                + " target=127.0.0.1 path=- status=200"),
        line);
    assertTrue(line.endsWith(" reason=-"), line);
    long deadline = System.currentTimeMillis() + 5_000;
    while (proxy.inFlight() > 0 && System.currentTimeMillis() < deadline) {
      Thread.sleep(20);
    }
    assertEquals(0, proxy.inFlight());
  }

  @Test
  void aConnectWithoutAGrantIsForbidden() throws Exception {
    // The route reaches this host and port, but CONNECT is not among its methods.
    Answer answer =
        raw(
            "CONNECT 127.0.0.1:" + upstream.actualPort() + " HTTP/1.1\r\nHost: 127.0.0.1\r\n"
                + "Proxy-Authorization: " + basic(token()) + "\r\n\r\n");
    assertEquals(403, answer.head().status());
    JsonObject body = new JsonObject(answer.body());
    assertEquals("no grant", body.getString("error"));
    assertEquals("CONNECT", body.getString("method"));
    assertEquals("suite", body.getString("route"));
    String line = auditLine();
    assertTrue(line.contains(" route=suite method=CONNECT target=127.0.0.1 path=- status=403"), line);
    assertTrue(line.endsWith(" reason=method-not-granted"), line);

    // No route reaches this one at all.
    answer =
        raw(
            "CONNECT api.example:443 HTTP/1.1\r\nHost: api.example:443\r\nProxy-Authorization: "
                + basic(token()) + "\r\n\r\n");
    assertEquals(403, answer.head().status());
    assertEquals("api.example:443", new JsonObject(answer.body()).getString("target"));
    assertTrue(auditLine().endsWith(" reason=no-grant"));
  }
}
