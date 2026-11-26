package eu.wohlben.qits.egress.proxy;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.fasterxml.jackson.databind.ObjectMapper;
import eu.wohlben.qits.egress.api.GrantTableWire;
import eu.wohlben.qits.egress.identity.Principal;
import eu.wohlben.qits.egress.grants.GrantIndex;
import eu.wohlben.qits.egress.grants.GrantRoute;
import eu.wohlben.qits.egress.store.GrantTableStore;
import eu.wohlben.qits.egress.testdb.SuiteIdp;
import eu.wohlben.qits.servicemock.idp.MockIdp;
import io.quarkus.test.junit.QuarkusTest;
import io.vertx.core.MultiMap;
import io.vertx.core.Vertx;
import io.vertx.core.http.HttpServer;
import io.vertx.core.json.JsonObject;
import jakarta.inject.Inject;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.List;
import java.util.UUID;
import java.util.concurrent.BlockingQueue;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.LinkedBlockingQueue;
import java.util.concurrent.TimeUnit;
import java.util.logging.Handler;
import java.util.logging.LogRecord;
import java.util.logging.Logger;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

/**
 * <b>Platform routes</b> (qits-2623): {@code platform:<label>} goes to the platform origin — in the
 * suites {@link SuiteIdp}'s {@code /platform/<label>} — with the caller's bearer exchanged at the
 * suite's idp, which mints what qits-idp mints: the caller's {@code sub} and groups, {@code act.sub}
 * the asking client. Cached per caller token; refused as 502; never handed to a third party.
 */
@QuarkusTest
class PlatformRouteTest {

  static final String SECRET = "suite-upstream-secret-value";

  static final String EDGE = "dev-qits-edge";

  static Vertx upstreamVertx;

  static HttpServer upstream;

  static final BlockingQueue<MultiMap> RECEIVED = new LinkedBlockingQueue<>();

  @Inject EgressProxy proxy;

  @Inject GrantTableStore store;

  @Inject GrantIndex index;

  @Inject ObjectMapper json;

  final HttpClient http = HttpClient.newHttpClient();

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
  static void startTheThirdParty() throws Exception {
    upstreamVertx = Vertx.vertx();
    upstream =
        upstreamVertx
            .createHttpServer()
            .requestHandler(
                request -> {
                  MultiMap headers = MultiMap.caseInsensitiveMultiMap();
                  headers.addAll(request.headers());
                  RECEIVED.add(headers);
                  request.response().end("third party answered");
                })
            .listen(0, "127.0.0.1")
            .toCompletionStage()
            .toCompletableFuture()
            .get(10, TimeUnit.SECONDS);
  }

  @AfterAll
  static void stopTheThirdParty() throws Exception {
    upstreamVertx.close().toCompletionStage().toCompletableFuture().get(10, TimeUnit.SECONDS);
  }

  GrantTableWire.GrantTable table() {
    return new GrantTableWire.GrantTable(
        System.currentTimeMillis(),
        List.of(
            new GrantTableWire.Route(
                "qits-edge", "dev", "1", "self-check", "platform:projects", null, null,
                List.of("GET")),
            new GrantTableWire.Route(
                "qits-edge", "dev", "1", "third", "http://127.0.0.1:" + upstream.actualPort() + "/base",
                "SUITE_UPSTREAM", "bearer", List.of("GET"))),
        List.of());
  }

  @BeforeEach
  void grant() throws Exception {
    RECEIVED.clear();
    SuiteIdp.refuseExchanges(null);
    SuiteIdp.exchangeLife(300);
    Logger.getLogger(AuditLine.LOGGER).addHandler(capture);
    GrantTableWire.GrantTable table = table();
    store.clear();
    store.store(table.version(), json.writeValueAsString(table), "application:qits-deployments");
    index.refresh();
  }

  @AfterEach
  void stopListening() {
    Logger.getLogger(AuditLine.LOGGER).removeHandler(capture);
    SuiteIdp.refuseExchanges(null);
    SuiteIdp.exchangeLife(300);
  }

  /** A caller token of its own per test, so the exchange cache starts empty for it. */
  private static String token() {
    return MockIdp.ensureStarted()
        .token()
        .subject(EDGE)
        .audience("qits-platform")
        .groups("clients/" + EDGE, "qits:system")
        .claim("nonce", UUID.randomUUID().toString())
        .mint();
  }

  private HttpResponse<String> call(String path, String token, String... headers) throws Exception {
    HttpRequest.Builder request =
        HttpRequest.newBuilder(URI.create("http://127.0.0.1:" + proxy.port() + path))
            .header("Authorization", "Bearer " + token);
    for (int i = 0; i < headers.length; i += 2) {
      request.header(headers[i], headers[i + 1]);
    }
    return http.send(request.build(), HttpResponse.BodyHandlers.ofString());
  }

  private String auditLine() throws InterruptedException {
    long deadline = System.currentTimeMillis() + 5_000;
    while (audit.isEmpty() && System.currentTimeMillis() < deadline) {
      Thread.sleep(20);
    }
    assertFalse(audit.isEmpty(), "an audit line was written");
    return audit.remove(0);
  }

  private static JsonObject claims(String authorization) {
    assertNotNull(authorization);
    assertTrue(authorization.startsWith("Bearer "), authorization);
    String[] parts = authorization.substring("Bearer ".length()).split("\\.");
    return new JsonObject(new String(Base64.getUrlDecoder().decode(parts[1]), StandardCharsets.UTF_8));
  }

  @Test
  void theTargetReceivesTheCallersSubjectActedByTheEgress() throws Exception {
    String token = token();
    HttpResponse<String> answer =
        call(
            "/self-check/projects/api/projects?state=live",
            token,
            "Cookie",
            "session=caller-cookie",
            "X-Qits-Project",
            "qits");
    assertEquals(200, answer.statusCode(), answer.body());
    assertEquals("{\"platform\":\"answered\"}", answer.body());
    assertEquals("/platform/projects/projects/api/projects?state=live", SuiteIdp.platformUri());

    JsonObject exchanged = claims(SuiteIdp.platformAuthorization());
    assertEquals(EDGE, exchanged.getString("sub"), "the caller is the subject");
    assertEquals(
        "dev-qits-egress",
        exchanged.getJsonObject("act").getString("sub"),
        "the egress is the actor: ${QITS_ENVIRONMENT}-qits-egress");
    assertTrue(exchanged.getJsonArray("groups").contains("clients/" + EDGE));
    assertNotEquals("Bearer " + token, SuiteIdp.platformAuthorization(), "never the caller's own");
    assertEquals("", SuiteIdp.platformLeaked(), "no cookie, no X-Qits-*, no secret header");
    assertEquals(
        "Basic "
            + Base64.getEncoder()
                .encodeToString("dev-qits-egress:suite-egress-secret".getBytes(StandardCharsets.UTF_8)),
        SuiteIdp.lastExchangeAuthorization(),
        "exchanged with this service's own client pair");

    String line = auditLine();
    assertTrue(
        line.startsWith(
            "egress decision=ALLOW principal=application:qits-edge route=self-check method=GET"
                + " target=127.0.0.1 path=/platform/projects/projects/api/projects status=200"),
        line);
    assertTrue(line.endsWith(" reason=-"), line);
    assertFalse(line.contains(token));
  }

  @Test
  void anExchangedBearerIsReusedUntilShortlyBeforeItExpires() throws Exception {
    String token = token();
    int exchanges = SuiteIdp.exchanges();
    int calls = SuiteIdp.platformCalls();
    assertEquals(200, call("/self-check/projects/api/one", token).statusCode());
    String first = SuiteIdp.platformAuthorization();
    assertEquals(200, call("/self-check/projects/api/two", token).statusCode());
    assertEquals(first, SuiteIdp.platformAuthorization(), "the cached bearer");
    assertEquals(exchanges + 1, SuiteIdp.exchanges(), "one exchange for two calls");
    assertEquals(calls + 2, SuiteIdp.platformCalls());

    // A token with less than 30 s to live is never cached.
    SuiteIdp.exchangeLife(20);
    String brief = token();
    int before = SuiteIdp.exchanges();
    assertEquals(200, call("/self-check/projects/api/three", brief).statusCode());
    assertEquals(200, call("/self-check/projects/api/four", brief).statusCode());
    assertEquals(before + 2, SuiteIdp.exchanges());
  }

  @Test
  void aRefusedExchangeIsABadGateway() throws Exception {
    SuiteIdp.refuseExchanges("invalid_grant");
    int calls = SuiteIdp.platformCalls();
    HttpResponse<String> answer = call("/self-check/projects/api/projects", token());
    assertEquals(502, answer.statusCode());
    assertEquals("{\"error\":\"token exchange refused\"}", answer.body());
    assertEquals(calls, SuiteIdp.platformCalls(), "nothing reached the platform service");
    String line = auditLine();
    assertTrue(line.contains("decision=DENY principal=application:qits-edge route=self-check"), line);
    assertTrue(line.contains(" status=502 "), line);
    assertTrue(line.endsWith(" reason=exchange-refused"), line);
  }

  @Test
  void aPlatformTokenIsNeverSentToAThirdParty() throws Exception {
    String token = token();
    assertEquals(200, call("/self-check/projects/api/projects", token).statusCode());
    String exchanged = SuiteIdp.platformAuthorization();
    auditLine();
    int exchanges = SuiteIdp.exchanges();

    // The same caller on a third-party route: the route's secret, never the exchanged bearer.
    assertEquals(200, call("/third/v1", token).statusCode());
    MultiMap received = RECEIVED.poll(5, TimeUnit.SECONDS);
    assertNotNull(received);
    assertEquals("Bearer " + SECRET, received.get("Authorization"));
    assertNotEquals(exchanged, received.get("Authorization"));
    assertEquals(exchanges, SuiteIdp.exchanges(), "a third-party route exchanges nothing");
    auditLine();

    // An https:// third-party origin with the platform route's path: no route, no exchange.
    try (java.net.Socket socket = new java.net.Socket("127.0.0.1", proxy.port())) {
      socket.setSoTimeout(10_000);
      socket
          .getOutputStream()
          .write(
              ("GET https://api.third-party.example/projects/api/projects HTTP/1.1\r\n"
                      + "Host: api.third-party.example\r\nProxy-Authorization: Bearer " + token
                      + "\r\nConnection: close\r\n\r\n")
                  .getBytes(StandardCharsets.ISO_8859_1));
      String head = new String(socket.getInputStream().readNBytes(12), StandardCharsets.ISO_8859_1);
      assertEquals("HTTP/1.1 403", head);
    }
    assertEquals(exchanges, SuiteIdp.exchanges());
    assertTrue(auditLine().endsWith(" reason=no-grant"));

    // And the interceptor that carries the bearer refuses any route that is not a platform route.
    GrantRoute third =
        GrantIndex.index(table(), true, SuiteIdp.platformOrigin()).route(new Principal(Principal.APPLICATION, "qits-edge"), "third");
    assertThrows(
        IllegalArgumentException.class,
        () -> new PlatformOutbound(third, "/base/x", "exchanged", new AuditLine("GET", "/x")));
    assertThrows(
        IllegalArgumentException.class,
        () -> PlatformOutbound.authorize(MultiMap.caseInsensitiveMultiMap(), third, "exchanged"));
  }

  @Test
  void anAbsoluteFormRequestToThePlatformOriginIsExchangedToo() throws Exception {
    String origin = SuiteIdp.platformOrigin().replace("{label}", "projects");
    try (java.net.Socket socket = new java.net.Socket("127.0.0.1", proxy.port())) {
      socket.setSoTimeout(10_000);
      socket
          .getOutputStream()
          .write(
              ("GET " + origin + "/projects/api/x HTTP/1.1\r\nHost: 127.0.0.1\r\n"
                      + "Proxy-Authorization: Bearer " + token() + "\r\nConnection: close\r\n\r\n")
                  .getBytes(StandardCharsets.ISO_8859_1));
      String head = new String(socket.getInputStream().readNBytes(12), StandardCharsets.ISO_8859_1);
      assertEquals("HTTP/1.1 200", head);
    }
    assertEquals("/platform/projects/projects/api/x", SuiteIdp.platformUri());
    assertEquals(EDGE, claims(SuiteIdp.platformAuthorization()).getString("sub"));
    assertTrue(auditLine().contains("decision=ALLOW principal=application:qits-edge route=self-check"));
  }
}
