package eu.wohlben.qits.egress.proxy;

import static eu.wohlben.qits.egress.proxy.ProxyWire.agentToken;
import static eu.wohlben.qits.egress.proxy.ProxyWire.basic;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.fasterxml.jackson.databind.ObjectMapper;
import eu.wohlben.qits.egress.api.GrantTableWire;
import eu.wohlben.qits.egress.grants.GrantIndex;
import eu.wohlben.qits.egress.store.GrantTableStore;
import eu.wohlben.qits.egress.support.SuiteTls;
import eu.wohlben.qits.egress.tls.LeafCertificates;
import eu.wohlben.qits.servicemock.idp.MockIdp;
import io.quarkus.test.junit.QuarkusTest;
import io.quarkus.test.junit.QuarkusTestProfile;
import io.quarkus.test.junit.TestProfile;
import io.vertx.core.MultiMap;
import io.vertx.core.Vertx;
import io.vertx.core.http.HttpServer;
import io.vertx.core.http.HttpServerOptions;
import io.vertx.core.net.KeyCertOptions;
import io.vertx.core.net.SocketAddress;
import jakarta.inject.Inject;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.io.UncheckedIOException;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.cert.X509Certificate;
import java.util.List;
import java.util.Map;
import java.util.concurrent.BlockingQueue;
import java.util.concurrent.LinkedBlockingQueue;
import java.util.concurrent.TimeUnit;
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
 * <b>A project's route through {@code CONNECT}, TLS ended here</b> (qits-2525, qits-2660) — the path
 * {@code curl -x … https://<host>/…} from an agent takes. An {@code agent:} of project {@code qits}
 * opens {@code CONNECT portal.project.test:<port>}, which its project's routes grant: the tunnel is
 * intercepted with the host's leaf, and the inner {@code GET} gets the route's secret — as a bearer
 * on one route, as {@code Cookie: sid=<secret>} on the other — with the caller's own credentials
 * gone and the upstream's {@code Set-Cookie} dropped. An agent of project {@code other} asking for
 * the same host holds no route: its {@code CONNECT :443} is the passthrough's blind splice, so its
 * TLS is the upstream's own (no leaf of ours), nothing is injected and {@code Set-Cookie} arrives.
 *
 * <p>The host is a made-up name with a dot, which the passthrough needs: the profile switches on
 * Vert.x' own resolver and hands it a hosts file mapping the name to loopback ({@code
 * quarkus.vertx.use-async-dns}, {@code quarkus.vertx.resolver.hosts-path}), which is how the
 * route's upstream pool reaches the fake https upstream; the passthrough resolves it through {@link
 * SuitePassthroughNetwork} to a "public" address, dialled on that same upstream.
 */
@QuarkusTest
@TestProfile(ProjectInterceptionTest.Hosts.class)
class ProjectInterceptionTest {

  static final String HOST = "portal.project.test";

  static final String HOST_ADDRESS = "203.0.113.9";

  static final String SECRET = "project-session-secret-value";

  /** Vert.x resolves {@value #HOST} to loopback, from a hosts file of the suite's own. */
  public static class Hosts implements QuarkusTestProfile {
    @Override
    public Map<String, String> getConfigOverrides() {
      try {
        Path hosts = Files.createDirectories(Path.of("target")).resolve("project-interception-hosts");
        Files.writeString(
            hosts, "127.0.0.1 localhost " + HOST + "\n::1 localhost\n", StandardCharsets.US_ASCII);
        // Quarkus' default is the JDK's resolver, which never reads a hosts file of ours; and an
        // earlier app in this JVM has already switched Vert.x' own off, read at each Vertx's start.
        System.clearProperty("vertx.disableDnsResolver");
        return Map.of(
            "quarkus.vertx.use-async-dns", "true",
            "quarkus.vertx.resolver.hosts-path", hosts.toAbsolutePath().toString());
      } catch (IOException e) {
        throw new UncheckedIOException(e);
      }
    }
  }

  record Received(String uri, MultiMap headers) {}

  static Vertx upstreamVertx;

  static HttpServer upstream;

  static final BlockingQueue<Received> RECEIVED = new LinkedBlockingQueue<>();

  @Inject EgressProxy proxy;

  @Inject GrantTableStore store;

  @Inject GrantIndex index;

  @Inject ObjectMapper json;

  @Inject LeafCertificates leaves;

  ProxyWire.Audit audit;

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
                  RECEIVED.add(new Received(request.uri(), headers));
                  request
                      .response()
                      .putHeader("Content-Type", "text/plain")
                      .putHeader("Set-Cookie", "session=fresh-from-the-login-page; Path=/")
                      .end("upstream answered");
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
    SuitePassthroughNetwork.NAMES.put(HOST, List.of(HOST_ADDRESS));
    SuitePassthroughNetwork.DIALS.put(
        HOST_ADDRESS + ":443", SocketAddress.inetSocketAddress(upstream.actualPort(), "127.0.0.1"));
    audit = new ProxyWire.Audit();
    String origin = "https://" + HOST + ":" + upstream.actualPort();
    GrantTableWire.GrantTable table =
        new GrantTableWire.GrantTable(
            System.currentTimeMillis(),
            List.of(
                route("portal-bearer", origin + "/bearer", "bearer"),
                route("portal-cookie", origin + "/cookie", "cookie:sid")),
            List.of());
    store.clear();
    store.store(table.version(), json.writeValueAsString(table), "application:qits-deployments");
    index.refresh();
  }

  @AfterEach
  void stopListening() {
    audit.close();
  }

  private static GrantTableWire.Route route(String name, String target, String inject) {
    return new GrantTableWire.Route(
        "project:qits",
        null,
        null,
        "0f1e2d3c4b5a",
        name,
        target,
        "PROJECT_QITS_SESSION",
        inject,
        List.of("CONNECT", "GET"));
  }

  /** An agent of another project, {@code other}. */
  private static String otherProjectsAgent() {
    return MockIdp.ensureStarted()
        .token()
        .subject("tok-agent-other-developer")
        .audience("qits-platform")
        .groups("qits:agent")
        .claim("agent", "stranger")
        .claim("project", "other")
        .mint();
  }

  // --- the wire ----------------------------------------------------------------------------------

  private Socket connect(String authority, String token) throws IOException {
    Socket socket = new Socket("127.0.0.1", proxy.port());
    socket.setSoTimeout(10_000);
    send(
        socket.getOutputStream(),
        "CONNECT " + authority + " HTTP/1.1\r\nHost: " + authority + "\r\nProxy-Authorization: "
            + basic(token) + "\r\n\r\n");
    return socket;
  }

  /** TLS over a tunnel for {@value #HOST}, trusting {@code ca} alone. */
  private static SSLSocket tls(Socket tunnel, String ca) throws Exception {
    SSLContext context = SuiteTls.ca(ca).clientContext();
    SSLSocket tls =
        (SSLSocket) context.getSocketFactory().createSocket(tunnel, HOST, tunnel.getPort(), true);
    SSLParameters parameters = tls.getSSLParameters();
    parameters.setServerNames(List.of(new SNIHostName(HOST)));
    parameters.setEndpointIdentificationAlgorithm("HTTPS");
    parameters.setApplicationProtocols(new String[] {"http/1.1"});
    tls.setSSLParameters(parameters);
    tls.startHandshake();
    return tls;
  }

  private static void send(OutputStream out, String head) throws IOException {
    out.write(head.getBytes(StandardCharsets.ISO_8859_1));
    out.flush();
  }

  /** An inner {@code GET} with the caller's own credentials and cookie on it. */
  private static String get(String path, String host) {
    return "GET " + path + " HTTP/1.1\r\nHost: " + host + "\r\n"
        + "Authorization: Bearer the-callers-own\r\n"
        + "Cookie: mine=the-callers-own\r\n\r\n";
  }

  private static X509Certificate peer(SSLSocket tls) throws Exception {
    return (X509Certificate) tls.getSession().getPeerCertificates()[0];
  }

  // --- the tests ---------------------------------------------------------------------------------

  @Test
  void anAgentOfTheProjectIsInterceptedAndInjectedBothWays() throws Exception {
    String authority = HOST + ":" + upstream.actualPort();
    try (Socket tunnel = connect(authority, agentToken())) {
      assertEquals(200, ProxyWire.head(tunnel.getInputStream()).status());
      try (SSLSocket tls = tls(tunnel, SuiteTls.LEAF)) {
        assertEquals(
            SuiteTls.ca(SuiteTls.LEAF).certificate().getSubjectX500Principal(),
            peer(tls).getIssuerX500Principal(),
            "TLS ended here, with our leaf for the host");
        assertEquals(
            leaves.leafFor(HOST).orElseThrow().serial(), peer(tls).getSerialNumber().toString(16));
        OutputStream out = tls.getOutputStream();
        InputStream in = tls.getInputStream();

        // The bearer route.
        send(out, get("/bearer/v1/me", authority));
        ProxyWire.Head answer = ProxyWire.head(in);
        assertEquals(200, answer.status());
        assertEquals("upstream answered", ProxyWire.body(in, answer));
        assertNull(answer.headers().get("Set-Cookie"), "a secret route hands out no session");
        Received received = RECEIVED.poll(5, TimeUnit.SECONDS);
        assertNotNull(received);
        assertEquals("/bearer/v1/me", received.uri());
        assertEquals("Bearer " + SECRET, received.headers().get("Authorization"), "injected");
        assertNull(received.headers().get("Cookie"), "the caller's cookie stays");
        assertNull(received.headers().get("Proxy-Authorization"));
        String line = audit.await(l -> l.contains(" method=GET "));
        assertTrue(
            line.startsWith(
                "egress decision=ALLOW principal=agent:developer route=portal-bearer method=GET"
                    + " target=" + HOST + " path=/bearer/v1/me status=200"),
            line);
        assertTrue(line.endsWith(" tls=intercepted"), line);

        // The cookie route, in the same tunnel.
        send(out, get("/cookie/v1/me", authority));
        answer = ProxyWire.head(in);
        assertEquals(200, answer.status());
        ProxyWire.body(in, answer);
        assertNull(answer.headers().get("Set-Cookie"));
        received = RECEIVED.poll(5, TimeUnit.SECONDS);
        assertNotNull(received);
        assertEquals("/cookie/v1/me", received.uri());
        assertEquals(List.of("sid=" + SECRET), received.headers().getAll("Cookie"), "injected");
        assertNull(received.headers().get("Authorization"), "the caller's bearer stays");
        line = audit.await(l -> l.contains(" method=GET "));
        assertTrue(line.contains(" principal=agent:developer route=portal-cookie "), line);
        assertTrue(line.endsWith(" tls=intercepted"), line);
        assertFalse(line.contains(SECRET), line);
      }
    }
    String connect = audit.await(l -> l.contains(" method=CONNECT "));
    assertTrue(
        connect.startsWith(
            "egress decision=ALLOW principal=agent:developer route=portal-bearer method=CONNECT"
                + " target=" + authority + " path=- status=200"),
        connect);
    assertTrue(connect.contains(" tls=intercepted leafSerial="), connect);
  }

  @Test
  void anAgentOfAnotherProjectIsSplicedBlindToTheSameHost() throws Exception {
    try (Socket tunnel = connect(HOST + ":443", otherProjectsAgent())) {
      assertEquals(200, ProxyWire.head(tunnel.getInputStream()).status());
      // Our leaf CA is no good here: the handshake is the upstream's own, end to end.
      try (SSLSocket tls = tls(tunnel, SuiteTls.UPSTREAM)) {
        assertEquals(
            SuiteTls.ca(SuiteTls.UPSTREAM).certificate().getSubjectX500Principal(),
            peer(tls).getIssuerX500Principal(),
            "no interception: the upstream's certificate");
        OutputStream out = tls.getOutputStream();
        InputStream in = tls.getInputStream();
        send(out, get("/cookie/v1/me", HOST));
        ProxyWire.Head answer = ProxyWire.head(in);
        assertEquals(200, answer.status());
        ProxyWire.body(in, answer);
        assertEquals(
            "session=fresh-from-the-login-page; Path=/",
            answer.headers().get("Set-Cookie"),
            "the caller's own session: passed on");
        Received received = RECEIVED.poll(5, TimeUnit.SECONDS);
        assertNotNull(received);
        assertEquals(List.of("mine=the-callers-own"), received.headers().getAll("Cookie"));
        assertEquals("Bearer the-callers-own", received.headers().get("Authorization"));
      }
    }
    String line = audit.await(l -> l.contains(" method=CONNECT "));
    assertTrue(
        line.startsWith(
            "egress decision=ALLOW principal=agent:stranger route=- method=CONNECT target=" + HOST
                + ":443 path=- status=200"),
        line);
    assertTrue(line.endsWith(" passthrough=true"), line);
    assertFalse(line.contains("tls=intercepted"), line);
    assertTrue(audit.lines.stream().noneMatch(l -> l.contains(" method=GET ")), "nothing seen inside");
  }

  @Test
  void anAgentOfAnotherProjectGetsNoGrantOnTheRoutesPort() throws Exception {
    // The route's own port is no passthrough port, and the route is not this agent's.
    try (Socket tunnel = connect(HOST + ":" + upstream.actualPort(), otherProjectsAgent())) {
      ProxyWire.Head answer = ProxyWire.head(tunnel.getInputStream());
      assertEquals(403, answer.status());
      ProxyWire.body(tunnel.getInputStream(), answer);
    }
    assertTrue(audit.await(l -> true).endsWith(" reason=passthrough-port"));
    assertTrue(RECEIVED.isEmpty());
  }
}
