package eu.wohlben.qits.egress.proxy;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.fasterxml.jackson.databind.ObjectMapper;
import eu.wohlben.qits.egress.api.GrantTableWire;
import eu.wohlben.qits.egress.grants.GrantIndex;
import eu.wohlben.qits.egress.store.GrantTableStore;
import eu.wohlben.qits.egress.support.SuiteTls;
import eu.wohlben.qits.egress.tls.LeafCertificates;
import eu.wohlben.qits.egress.tls.SuiteLeafIssuer;
import eu.wohlben.qits.egress.tls.TlsSelfCheck;
import eu.wohlben.qits.servicemock.idp.MockIdp;
import io.quarkus.test.junit.QuarkusTest;
import io.vertx.core.MultiMap;
import io.vertx.core.Vertx;
import io.vertx.core.http.HttpServer;
import io.vertx.core.http.HttpServerOptions;
import io.vertx.core.http.HttpServerResponse;
import io.vertx.core.json.JsonObject;
import io.vertx.core.net.KeyCertOptions;
import jakarta.inject.Inject;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.security.cert.X509Certificate;
import java.util.Base64;
import java.util.List;
import java.util.concurrent.BlockingQueue;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.LinkedBlockingQueue;
import java.util.concurrent.TimeUnit;
import java.util.logging.Handler;
import java.util.logging.LogRecord;
import java.util.logging.Logger;
import javax.net.ssl.SNIHostName;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLParameters;
import javax.net.ssl.SSLSocket;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

/**
 * <b>TLS ended inside a {@code CONNECT} tunnel</b> (qits-2644), through the real listeners: the
 * leaves come from {@link SuiteLeafIssuer} ({@link SuiteTls#LEAF} standing in for qits-certificates),
 * the third party is a fake https upstream on {@code localhost} whose certificate {@link
 * SuiteTls#UPSTREAM} signed — trusted by the upstream pools only through the suites' {@code
 * qits.egress.test.upstream-trust}. The client is a raw socket: the {@code CONNECT}, then the JDK's
 * {@link SSLSocket} over it with SNI {@code localhost}, trusting the leaf CA alone.
 */
@QuarkusTest
class EgressInterceptionTest {

  static final String SECRET = "suite-upstream-secret-value";

  static final String EDGE = "dev-qits-edge";

  static final String HOST = "localhost";

  /** A host whose leaf the suite CA refuses. */
  static final String REFUSED = "refused.egress.test";

  static final long STREAM_GAP_MILLIS = 1_500;

  record Received(String method, String uri, MultiMap headers) {}

  static Vertx upstreamVertx;

  static HttpServer upstream;

  static final BlockingQueue<Received> RECEIVED = new LinkedBlockingQueue<>();

  @Inject EgressProxy proxy;

  @Inject GrantTableStore store;

  @Inject GrantIndex index;

  @Inject ObjectMapper json;

  @Inject LeafCertificates leaves;

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
  static void startTheUpstream() throws Exception {
    upstreamVertx = Vertx.vertx();
    upstream =
        upstreamVertx
            .createHttpServer(
                new HttpServerOptions()
                    .setSsl(true)
                    .setKeyCertOptions(
                        KeyCertOptions.wrap(SuiteTls.ca(SuiteTls.UPSTREAM).server(HOST))))
            .requestHandler(
                request -> {
                  MultiMap headers = MultiMap.caseInsensitiveMultiMap();
                  headers.addAll(request.headers());
                  RECEIVED.add(new Received(request.method().name(), request.uri(), headers));
                  HttpServerResponse response = request.response();
                  if (request.path().equals("/v1/events")) {
                    response
                        .setChunked(true)
                        .putHeader("Content-Type", "text/event-stream")
                        .write("data: one\n\n");
                    upstreamVertx.setTimer(STREAM_GAP_MILLIS, t -> response.end("data: two\n\n"));
                    return;
                  }
                  response.putHeader("Content-Type", "text/plain").end("upstream answered " + SECRET);
                })
            .listen(0, "127.0.0.1")
            .toCompletionStage()
            .toCompletableFuture()
            .get(10, TimeUnit.SECONDS);
  }

  @AfterAll
  static void stopTheUpstream() throws Exception {
    upstreamVertx.close().toCompletionStage().toCompletableFuture().get(10, TimeUnit.SECONDS);
  }

  @BeforeEach
  void grant() throws Exception {
    RECEIVED.clear();
    SuiteLeafIssuer.REFUSED.add(REFUSED);
    Logger.getLogger(AuditLine.LOGGER).addHandler(capture);
    String target = "https://" + HOST + ":" + upstream.actualPort();
    GrantTableWire.GrantTable table =
        new GrantTableWire.GrantTable(
            System.currentTimeMillis(),
            List.of(
                route("qits-edge", "intercepted", target, "SUITE_UPSTREAM", "bearer", "CONNECT", "GET"),
                route("qits-edge", "no-connect", "https://elsewhere.egress.test", "SUITE_UPSTREAM", "bearer", "GET"),
                route("qits-edge", "refused", "https://" + REFUSED, "SUITE_UPSTREAM", "bearer", "CONNECT"),
                route("qits-egress", TlsSelfCheck.ROUTE, target, "SUITE_UPSTREAM", "bearer", "CONNECT", "HEAD")),
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
      String application, String name, String target, String secret, String inject, String... methods) {
    return new GrantTableWire.Route(
        application, "dev", "2026.1201.101010", name, target, secret, inject, List.of(methods));
  }

  static String token(String client) {
    return MockIdp.ensureStarted()
        .token()
        .subject(client)
        .audience("qits-platform")
        .groups("clients/" + client, "qits:system")
        .mint();
  }

  private static String basic(String token) {
    return "Basic "
        + Base64.getEncoder().encodeToString(("anyone:" + token).getBytes(StandardCharsets.UTF_8));
  }

  /** The next audit line that satisfies nothing but arriving; waits up to 5 s. */
  private String auditLine() throws InterruptedException {
    long deadline = System.currentTimeMillis() + 5_000;
    while (audit.isEmpty() && System.currentTimeMillis() < deadline) {
      Thread.sleep(20);
    }
    assertFalse(audit.isEmpty(), "an audit line was written");
    return audit.remove(0);
  }

  // --- the wire ----------------------------------------------------------------------------------

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

  /** A chunk-size line, the chunk, its CRLF; null at the last chunk. */
  private static String chunk(InputStream in) throws IOException {
    StringBuilder size = new StringBuilder();
    int b;
    while ((b = in.read()) != '\n') {
      if (b < 0) {
        throw new IOException("closed inside a chunk size");
      }
      if (b != '\r') {
        size.append((char) b);
      }
    }
    int n = Integer.parseInt(size.toString().trim(), 16);
    if (n == 0) {
      in.readNBytes(2);
      return null;
    }
    String body = new String(in.readNBytes(n), StandardCharsets.UTF_8);
    in.readNBytes(2);
    return body;
  }

  private static String body(InputStream in, Head head) throws IOException {
    String length = head.headers().get("Content-Length");
    if (length != null) {
      return new String(in.readNBytes(Integer.parseInt(length)), StandardCharsets.UTF_8);
    }
    StringBuilder body = new StringBuilder();
    String part;
    while ((part = chunk(in)) != null) {
      body.append(part);
    }
    return body.toString();
  }

  /** A {@code CONNECT} on a fresh socket to the proxy; the socket, past the {@code 200}. */
  private Socket connect(String authority, String credential) throws IOException {
    Socket socket = new Socket("127.0.0.1", proxy.port());
    socket.setSoTimeout(10_000);
    OutputStream out = socket.getOutputStream();
    out.write(
        ("CONNECT " + authority + " HTTP/1.1\r\nHost: " + authority + "\r\nProxy-Authorization: "
                + credential + "\r\n\r\n")
            .getBytes(StandardCharsets.ISO_8859_1));
    out.flush();
    return socket;
  }

  /** TLS over a tunnel, trusting the leaf CA alone, asking for {@code sni}. */
  private static SSLSocket tls(Socket tunnel, String sni) throws Exception {
    SSLContext context = SuiteTls.ca(SuiteTls.LEAF).clientContext();
    SSLSocket tls =
        (SSLSocket)
            context.getSocketFactory().createSocket(tunnel, sni, tunnel.getPort(), true);
    SSLParameters parameters = tls.getSSLParameters();
    parameters.setServerNames(List.of(new SNIHostName(sni)));
    parameters.setEndpointIdentificationAlgorithm("HTTPS");
    parameters.setApplicationProtocols(new String[] {"h2", "http/1.1"});
    tls.setSSLParameters(parameters);
    tls.startHandshake();
    return tls;
  }

  private static void send(OutputStream out, String head) throws IOException {
    out.write(head.getBytes(StandardCharsets.ISO_8859_1));
    out.flush();
  }

  // --- the tests ---------------------------------------------------------------------------------

  @Test
  void aTunnelsTlsEndsWithTheHostsLeafAndItsRequestsGetTheSecret() throws Exception {
    String authority = HOST + ":" + upstream.actualPort();
    String token = token(EDGE);
    try (Socket tunnel = connect(authority, basic(token))) {
      Head connected = head(tunnel.getInputStream());
      assertEquals(200, connected.status());
      try (SSLSocket tls = tls(tunnel, HOST)) {
        assertEquals("http/1.1", tls.getApplicationProtocol(), "ALPN offers http/1.1 only");
        X509Certificate leaf = (X509Certificate) tls.getSession().getPeerCertificates()[0];
        assertEquals(
            SuiteTls.ca(SuiteTls.LEAF).certificate().getSubjectX500Principal(),
            leaf.getIssuerX500Principal(),
            "the leaf is the suite CA's");
        assertTrue(
            leaf.getSubjectAlternativeNames().stream().anyMatch(name -> HOST.equals(name.get(1))),
            "the leaf names the host");
        assertEquals(
            leaves.leafFor(HOST).orElseThrow().serial(), leaf.getSerialNumber().toString(16));
        assertTrue(proxy.inFlight() >= 1, "an open intercepted tunnel is a call in flight");
        assertEquals(1, proxy.interceptedTunnels());

        OutputStream out = tls.getOutputStream();
        InputStream in = tls.getInputStream();
        send(
            out,
            "GET /v1/zones?name=q HTTP/1.1\r\nHost: " + authority + "\r\n"
                + "Authorization: Bearer caller-own-target-credential\r\n"
                + "Proxy-Authorization: " + basic(token) + "\r\n"
                + "Cookie: session=caller\r\n\r\n");
        Head answer = head(in);
        assertEquals(200, answer.status());
        assertEquals("upstream answered [redacted]", body(in, answer), "scrubbed");
        Received received = RECEIVED.poll(5, TimeUnit.SECONDS);
        assertNotNull(received);
        assertEquals("/v1/zones?name=q", received.uri());
        assertEquals("Bearer " + SECRET, received.headers().get("Authorization"), "injected");
        assertNull(received.headers().get("Proxy-Authorization"), "the caller's credential stays");
        assertNull(received.headers().get("Cookie"));
        assertEquals("identity", received.headers().get("Accept-Encoding"));
        String line = auditLine();
        assertTrue(
            line.startsWith(
                "egress decision=ALLOW principal=application:qits-edge route=intercepted method=GET"
                    + " target=localhost path=/v1/zones status=200"),
            line);
        assertTrue(line.endsWith(" reason=- tls=intercepted"), line);
        assertFalse(line.contains(token));

        // The inner method is checked: the route grants CONNECT and GET, not DELETE.
        send(out, "DELETE /v1/zones/1 HTTP/1.1\r\nHost: " + authority + "\r\n\r\n");
        answer = head(in);
        assertEquals(403, answer.status());
        JsonObject refused = new JsonObject(body(in, answer));
        assertEquals("no grant", refused.getString("error"));
        assertEquals("intercepted", refused.getString("route"));
        line = auditLine();
        assertTrue(line.contains(" method=DELETE "), line);
        assertTrue(line.endsWith(" reason=method-not-granted tls=intercepted"), line);

        // A Host that is not the tunnel's: 421.
        send(out, "GET /v1/zones HTTP/1.1\r\nHost: api.example.org\r\n\r\n");
        answer = head(in);
        assertEquals(421, answer.status());
        body(in, answer);
        assertTrue(auditLine().endsWith(" reason=misdirected tls=intercepted"));
        assertTrue(RECEIVED.isEmpty(), "nothing refused reached the upstream");
      }
    }
    String connectLine = auditLine();
    assertTrue(
        connectLine.startsWith(
            "egress decision=ALLOW principal=application:qits-edge route=intercepted method=CONNECT"
                + " target=" + authority + " path=- status=200"),
        connectLine);
    assertTrue(
        connectLine.endsWith(
            " tls=intercepted leafSerial=" + leaves.leafFor(HOST).orElseThrow().serial()),
        connectLine);
    long deadline = System.currentTimeMillis() + 5_000;
    while ((proxy.inFlight() > 0 || proxy.interceptedTunnels() > 0)
        && System.currentTimeMillis() < deadline) {
      Thread.sleep(20);
    }
    assertEquals(0, proxy.inFlight());
    assertEquals(0, proxy.interceptedTunnels(), "the tunnel's entry is gone with it");
  }

  @Test
  void aConnectWhoseHostGetsNoLeafIs503() throws Exception {
    try (Socket tunnel = connect(REFUSED + ":443", basic(token(EDGE)))) {
      Head answer = head(tunnel.getInputStream());
      assertEquals(503, answer.status());
      assertEquals(
          "no certificate for the host yet",
          new JsonObject(body(tunnel.getInputStream(), answer)).getString("error"));
    }
    String line = auditLine();
    assertTrue(
        line.startsWith(
            "egress decision=DENY principal=application:qits-edge route=refused method=CONNECT"
                + " target=" + REFUSED + ":443 path=- status=503"),
        line);
    assertTrue(line.endsWith(" reason=no-leaf"), line);
  }

  @Test
  void aConnectToARouteWithoutConnectIsForbidden() throws Exception {
    try (Socket tunnel = connect("elsewhere.egress.test:443", basic(token(EDGE)))) {
      Head answer = head(tunnel.getInputStream());
      assertEquals(403, answer.status());
      assertEquals("no-connect", new JsonObject(body(tunnel.getInputStream(), answer)).getString("route"));
    }
    assertTrue(auditLine().endsWith(" reason=method-not-granted"));
  }

  @Test
  void aHandshakeForAnotherNameThanTheTunnelsFails() throws Exception {
    String authority = HOST + ":" + upstream.actualPort();
    try (Socket tunnel = connect(authority, basic(token(EDGE)))) {
      assertEquals(200, head(tunnel.getInputStream()).status());
      // No leaf is held for this name: there is no certificate to offer.
      assertThrows(IOException.class, () -> tls(tunnel, "unknown.egress.test"));
    }
    auditLine();
  }

  @Test
  void anEventStreamFlowsThroughTheTunnelUnbuffered() throws Exception {
    String authority = HOST + ":" + upstream.actualPort();
    try (Socket tunnel = connect(authority, basic(token(EDGE)))) {
      assertEquals(200, head(tunnel.getInputStream()).status());
      try (SSLSocket tls = tls(tunnel, HOST)) {
        InputStream in = tls.getInputStream();
        long started = System.nanoTime();
        send(
            tls.getOutputStream(),
            "GET /v1/events HTTP/1.1\r\nHost: " + authority + "\r\nAccept: text/event-stream\r\n\r\n");
        Head answer = head(in);
        assertEquals(200, answer.status());
        StringBuilder events = new StringBuilder();
        while (!events.toString().contains("data: one")) {
          String part = chunk(in);
          assertNotNull(part, "the stream ended before its first event: " + events);
          events.append(part);
        }
        long firstMillis = (System.nanoTime() - started) / 1_000_000;
        assertTrue(
            firstMillis < STREAM_GAP_MILLIS,
            "the first event arrived after " + firstMillis + " ms, before the upstream ended");
        String part;
        while ((part = chunk(in)) != null) {
          events.append(part);
        }
        assertEquals("data: one\n\ndata: two\n\n", events.toString());
      }
    }
    String line = auditLine();
    assertTrue(line.contains(" route=intercepted method=GET target=localhost path=/v1/events status=200"), line);
  }

  @Test
  void theSelfCheckHandshakesTrustingOnlyThePublishedAnchors() throws Exception {
    leaves.issueNow(HOST).toCompletableFuture().get(10, TimeUnit.SECONDS);
    X509Certificate anchor = SuiteTls.ca(SuiteTls.LEAF).certificate();
    TlsSelfCheck.Outcome outcome =
        TlsSelfCheck.probe(
            proxy.port(),
            HOST,
            upstream.actualPort(),
            token("dev-qits-egress"),
            TlsSelfCheck.Anchors.of("v1", List.of(anchor)),
            10_000);
    assertEquals(200, outcome.status());
    assertEquals(leaves.leafFor(HOST).orElseThrow().serial(), outcome.leafSerial());
    assertEquals(anchor.getSubjectX500Principal().getName(), outcome.issuer());
    Received received = RECEIVED.poll(5, TimeUnit.SECONDS);
    assertNotNull(received);
    assertEquals("HEAD", received.method());
    assertEquals("/v1/", received.uri());
    assertEquals("Bearer " + SECRET, received.headers().get("Authorization"));

    // Anchors that are not the leaf's: the handshake is refused, whatever else would trust it.
    X509Certificate other = SuiteTls.ca(SuiteTls.UPSTREAM).certificate();
    TlsSelfCheck.CheckFailed failed =
        assertThrows(
            TlsSelfCheck.CheckFailed.class,
            () ->
                TlsSelfCheck.probe(
                    proxy.port(),
                    HOST,
                    upstream.actualPort(),
                    token("dev-qits-egress"),
                    TlsSelfCheck.Anchors.of("v2", List.of(other)),
                    10_000));
    assertTrue(failed.getMessage().startsWith("the handshake failed"), failed.getMessage());
  }
}
