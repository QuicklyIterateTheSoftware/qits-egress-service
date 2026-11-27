package eu.wohlben.qits.egress.proxy;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.fasterxml.jackson.databind.ObjectMapper;
import eu.wohlben.qits.egress.api.GrantTableWire;
import eu.wohlben.qits.egress.grants.GrantIndex;
import eu.wohlben.qits.egress.store.GrantTableStore;
import eu.wohlben.qits.egress.support.SuiteTls;
import eu.wohlben.qits.egress.support.SuiteWorkloads;
import eu.wohlben.qits.egress.tls.TlsProxySelfCheck;
import eu.wohlben.qits.egress.tls.TlsProxyWiring;
import eu.wohlben.qits.servicemock.idp.MockIdp;
import io.quarkus.test.junit.QuarkusTest;
import io.vertx.core.MultiMap;
import io.vertx.core.Vertx;
import io.vertx.core.http.HttpServer;
import io.vertx.core.json.JsonObject;
import jakarta.inject.Inject;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
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
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.KeyPurposeId;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

/**
 * <b>The TLS proxy listener</b> (8082, qits-2759) through real handshakes: its server certificate
 * is the suites' workload certificate for {@code application:qits-egress} ({@code
 * tls/SuiteWorkloadTls}), and it trusts the {@link SuiteWorkloads#ANCHOR} CA alone, as a deployment
 * trusts the platform anchors. A bearer still decides; without one, the client certificate does;
 * an interception leaf, another CA's certificate and one of two principals are refused.
 */
@QuarkusTest
class TlsProxyListenerTest {

  static final String SECRET = "suite-upstream-secret-value";

  static final String EDGE = "dev-qits-edge";

  record Received(String uri, MultiMap headers) {}

  static Vertx upstreamVertx;

  static HttpServer upstream;

  static final BlockingQueue<Received> RECEIVED = new LinkedBlockingQueue<>();

  @Inject EgressProxy proxy;

  @Inject GrantTableStore store;

  @Inject GrantIndex index;

  @Inject ObjectMapper json;

  @Inject TlsProxyWiring wiring;

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
  }

  @AfterAll
  static void stopTheUpstream() throws Exception {
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
                new GrantTableWire.Route(
                    "qits-edge",
                    "dev",
                    "2026.1201.101010",
                    "suite",
                    target + "/base",
                    "SUITE_UPSTREAM",
                    "header:X-Api-Key",
                    List.of("GET"))),
            List.of());
    store.clear();
    store.store(table.version(), json.writeValueAsString(table), "application:qits-deployments");
    index.refresh();
  }

  @AfterEach
  void stopListening() {
    Logger.getLogger(AuditLine.LOGGER).removeHandler(capture);
  }

  // --- the tests --------------------------------------------------------------------------------

  @Test
  void aCallerWithACertificateAndNoBearerIsGrantedItsRoutes() throws Exception {
    SuiteWorkloads.Pair edge = SuiteWorkloads.application("qits-edge");
    Answer answer = call(SuiteWorkloads.client(edge), "GET /suite/v1 HTTP/1.1\r\nHost: localhost\r\n");
    assertEquals(200, answer.status(), answer.body());
    assertEquals("upstream answered", answer.body());
    Received received = RECEIVED.poll(5, TimeUnit.SECONDS);
    assertEquals("/base/v1", received.uri());
    assertEquals(SECRET, received.headers().get("X-Api-Key"));
    String line = auditLine();
    assertTrue(line.startsWith("egress decision=ALLOW principal=application:qits-edge route=suite"), line);
    assertTrue(
        line.endsWith(
            " reason=- auth=certificate clientSerial="
                + edge.certificate().getSerialNumber().toString(16)),
        line);
  }

  @Test
  void theAbsoluteFormTakesTheCertificateToo() throws Exception {
    SuiteWorkloads.Pair edge = SuiteWorkloads.application("qits-edge");
    String url = "http://127.0.0.1:" + upstream.actualPort() + "/base/abs";
    Answer answer =
        call(SuiteWorkloads.client(edge), "GET " + url + " HTTP/1.1\r\nHost: 127.0.0.1\r\n");
    assertEquals(200, answer.status(), answer.body());
    assertEquals("/base/abs", RECEIVED.poll(5, TimeUnit.SECONDS).uri());
    assertTrue(auditLine().contains(" auth=certificate clientSerial="));
  }

  @Test
  void aBearerStillDecidesWhenBothAreSent() throws Exception {
    // A certificate of an agent with no routes, and qits-edge's bearer: the bearer decides.
    SuiteWorkloads.Pair agent =
        SuiteWorkloads.agent("6fe232fc-0000-4000-8000-000000000001", "qits");
    Answer granted =
        call(
            SuiteWorkloads.client(agent),
            "GET /suite/v1 HTTP/1.1\r\nHost: localhost\r\nAuthorization: Bearer " + token() + "\r\n");
    assertEquals(200, granted.status(), granted.body());
    String line = auditLine();
    assertTrue(line.contains(" principal=application:qits-edge "), line);
    assertTrue(line.endsWith(" auth=bearer"), line);

    // And a bad bearer beside a good certificate is a bad bearer.
    Answer refused =
        call(
            SuiteWorkloads.client(SuiteWorkloads.application("qits-edge")),
            "GET /suite/v1 HTTP/1.1\r\nHost: localhost\r\nAuthorization: Bearer nonsense\r\n");
    assertEquals(401, refused.status(), refused.body());
    assertTrue(auditLine().endsWith(" auth=bearer"));
  }

  @Test
  void anAgentCertificateNamesTheAgentAndHoldsItsProjectsRoutes() throws Exception {
    Answer answer =
        call(
            SuiteWorkloads.client(
                SuiteWorkloads.agent("6fe232fc-0000-4000-8000-000000000001", "qits")),
            "GET /suite/v1 HTTP/1.1\r\nHost: localhost\r\n");
    // project:qits holds no route here: the 403 names the agent the certificate said.
    assertEquals(403, answer.status(), answer.body());
    assertEquals(
        "agent:6fe232fc-0000-4000-8000-000000000001",
        new JsonObject(answer.body()).getString("principal"));
  }

  @Test
  void anInterceptionLeafIsRefusedAsAClientCertificate() throws Exception {
    // Signed by the anchor, as qits-certificates signs egress' interception leaves: serverAuth only.
    SuiteWorkloads.Pair leaf =
        SuiteWorkloads.sign(
            SuiteTls.ca(SuiteWorkloads.ANCHOR),
            List.of(new GeneralName(GeneralName.dNSName, "api.hetzner.cloud")),
            KeyPurposeId.id_kp_serverAuth);
    assertThrows(
        IOException.class,
        () ->
            call(
                SuiteWorkloads.clientInsisting(leaf),
                "GET /suite/v1 HTTP/1.1\r\nHost: localhost\r\n"));
    assertTrue(RECEIVED.isEmpty());
  }

  @Test
  void aCertificateFromAnotherCaIsRefused() throws Exception {
    SuiteWorkloads.Pair stranger =
        SuiteWorkloads.sign(
            SuiteTls.ca(SuiteWorkloads.STRANGER),
            List.of(
                new GeneralName(
                    GeneralName.uniformResourceIdentifier,
                    SuiteWorkloads.PRINCIPAL + "application:qits-edge")),
            KeyPurposeId.id_kp_clientAuth);
    assertThrows(
        IOException.class,
        () ->
            call(
                SuiteWorkloads.clientInsisting(stranger),
                "GET /suite/v1 HTTP/1.1\r\nHost: localhost\r\n"));
    assertTrue(RECEIVED.isEmpty());
  }

  @Test
  void aCertificateOfTwoPrincipalsNamesNone() throws Exception {
    SuiteWorkloads.Pair two =
        SuiteWorkloads.sign(
            SuiteTls.ca(SuiteWorkloads.ANCHOR),
            List.of(
                new GeneralName(
                    GeneralName.uniformResourceIdentifier,
                    SuiteWorkloads.PRINCIPAL + "application:qits-edge"),
                new GeneralName(
                    GeneralName.uniformResourceIdentifier,
                    SuiteWorkloads.PRINCIPAL + "application:qits-idp")),
            KeyPurposeId.id_kp_clientAuth);
    Answer answer = call(SuiteWorkloads.client(two), "GET /suite/v1 HTTP/1.1\r\nHost: localhost\r\n");
    assertEquals(401, answer.status());
    String line = auditLine();
    assertTrue(line.contains(" reason=certificate-no-principal "), line);
    assertTrue(line.contains(" auth=certificate clientSerial="), line);
  }

  @Test
  void neitherABearerNorACertificateIs401Or407() throws Exception {
    Answer gateway = call(SuiteWorkloads.client(null), "GET /suite/v1 HTTP/1.1\r\nHost: localhost\r\n");
    assertEquals(401, gateway.status());
    assertTrue(auditLine().contains(" reason=no-credentials "));
    String url = "http://127.0.0.1:" + upstream.actualPort() + "/base/abs";
    Answer proxyForm =
        call(SuiteWorkloads.client(null), "GET " + url + " HTTP/1.1\r\nHost: 127.0.0.1\r\n");
    assertEquals(407, proxyForm.status());
  }

  @Test
  void theSelfCheckProbeIsTakenForQitsEgress() throws Exception {
    TlsProxySelfCheck.Outcome outcome =
        TlsProxySelfCheck.probe(
            wiring.tls().clientContext(), tlsPort(), "dev-qits-egress", 5_000);
    assertEquals("application:qits-egress", outcome.principal());
    assertEquals(
        wiring.tls().certificate().getSerialNumber().toString(16), outcome.serverSerial());
  }

  @Test
  void port8081WritesNoAuthField() throws Exception {
    try (Socket socket = new Socket()) {
      socket.connect(new InetSocketAddress("127.0.0.1", proxy.port()), 5_000);
      socket.setSoTimeout(5_000);
      socket
          .getOutputStream()
          .write(
              ("GET /suite/v1 HTTP/1.1\r\nHost: 127.0.0.1\r\nAuthorization: Bearer " + token()
                      + "\r\nConnection: close\r\n\r\n")
                  .getBytes(StandardCharsets.ISO_8859_1));
      socket.getInputStream().readAllBytes();
    }
    String line = auditLine();
    assertTrue(line.endsWith(" reason=-"), line);
    assertFalse(line.contains("auth="), line);
  }

  // --- helpers ----------------------------------------------------------------------------------

  private static String token() {
    return MockIdp.ensureStarted()
        .token()
        .subject(EDGE)
        .audience("qits-platform")
        .groups("clients/" + EDGE, "qits:system")
        .mint();
  }

  private int tlsPort() throws InterruptedException {
    long deadline = System.currentTimeMillis() + 10_000;
    while (proxy.tlsProxyPort() < 0 && System.currentTimeMillis() < deadline) {
      Thread.sleep(50);
    }
    assertTrue(proxy.tlsProxyPort() > 0, "8082 opened once a certificate was held");
    return proxy.tlsProxyPort();
  }

  private String auditLine() throws InterruptedException {
    long deadline = System.currentTimeMillis() + 5_000;
    while (audit.isEmpty() && System.currentTimeMillis() < deadline) {
      Thread.sleep(20);
    }
    assertFalse(audit.isEmpty(), "an audit line was written");
    return audit.remove(0);
  }

  record Answer(int status, String body) {}

  /** One request over a fresh TLS connection to 8082, host name checked as {@code localhost}. */
  private Answer call(SSLContext context, String head) throws Exception {
    int port = tlsPort();
    try (Socket raw = new Socket()) {
      raw.connect(new InetSocketAddress("127.0.0.1", port), 5_000);
      raw.setSoTimeout(5_000);
      try (SSLSocket tls =
          (SSLSocket) context.getSocketFactory().createSocket(raw, "localhost", port, true)) {
        SSLParameters parameters = tls.getSSLParameters();
        parameters.setServerNames(List.of(new SNIHostName("localhost")));
        parameters.setEndpointIdentificationAlgorithm("HTTPS");
        tls.setSSLParameters(parameters);
        tls.startHandshake();
        OutputStream out = tls.getOutputStream();
        out.write((head + "Connection: close\r\n\r\n").getBytes(StandardCharsets.ISO_8859_1));
        out.flush();
        InputStream in = tls.getInputStream();
        String response = new String(readAll(in), StandardCharsets.UTF_8);
        if (response.isEmpty()) {
          throw new IOException("closed without a response");
        }
        int split = response.indexOf("\r\n\r\n");
        String status = response.substring(0, response.indexOf("\r\n")).split(" ")[1];
        String rest = split < 0 ? "" : response.substring(split + 4);
        String lengthHeader = header(response.substring(0, Math.max(split, 0)), "content-length");
        if (lengthHeader == null && rest.contains("\r\n")) {
          rest = unchunk(rest);
        }
        return new Answer(Integer.parseInt(status), rest);
      }
    }
  }

  private static byte[] readAll(InputStream in) throws IOException {
    ByteArrayOutputStream bytes = new ByteArrayOutputStream();
    byte[] buffer = new byte[4096];
    int n;
    while ((n = in.read(buffer)) >= 0) {
      bytes.write(buffer, 0, n);
    }
    return bytes.toByteArray();
  }

  private static String header(String head, String name) {
    for (String line : head.split("\r\n")) {
      int colon = line.indexOf(':');
      if (colon > 0 && line.substring(0, colon).trim().equalsIgnoreCase(name)) {
        return line.substring(colon + 1).trim();
      }
    }
    return null;
  }

  private static String unchunk(String chunked) {
    StringBuilder body = new StringBuilder();
    String rest = chunked;
    while (true) {
      int eol = rest.indexOf("\r\n");
      if (eol < 0) {
        return body.toString();
      }
      int size = Integer.parseInt(rest.substring(0, eol).trim(), 16);
      if (size == 0) {
        return body.toString();
      }
      body.append(rest, eol + 2, eol + 2 + size);
      rest = rest.substring(eol + 2 + size + 2);
    }
  }
}
