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
 * <b>The gateway form through the real listener</b>, against a fake upstream on plain http (the
 * suite's {@code qits.egress.test.allow-plain-http}), and {@link SuiteIdp} for discovery and a set
 * token introspection in front of this JVM's {@link MockIdp}, which mints the callers' tokens.
 *
 * <p>What it proves: the route's secret arrives upstream in its header and the caller's {@code
 * Authorization}, {@code Cookie} and {@code X-Qits-*} do not; 403 for an ungranted route, for a
 * method outside {@code methods} and for a caller that is not an application; 401 without a bearer
 * or with a bad one; 503 with no table; 502 for a secret this process does not hold; 501 for a
 * platform route; an opaque token introspected once and then cached; and exactly one audit line per
 * call, carrying no query, no header value and no secret.
 */
@QuarkusTest
class EgressGatewayTest {

  static final String SECRET = "suite-upstream-secret-value";

  static final String EDGE = "dev-qits-edge";

  record Received(String method, String uri, MultiMap headers, String body) {}

  static Vertx upstreamVertx;

  static HttpServer upstream;

  static final BlockingQueue<Received> RECEIVED = new LinkedBlockingQueue<>();

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
  static void startTheUpstream() throws Exception {
    upstreamVertx = Vertx.vertx();
    upstream =
        upstreamVertx
            .createHttpServer()
            .requestHandler(
                request ->
                    request
                        .body()
                        .onSuccess(
                            body -> {
                              MultiMap headers = MultiMap.caseInsensitiveMultiMap();
                              headers.addAll(request.headers());
                              RECEIVED.add(
                                  new Received(
                                      request.method().name(),
                                      request.uri(),
                                      headers,
                                      body.toString()));
                              request
                                  .response()
                                  .putHeader("Content-Type", "application/json")
                                  .end("{\"upstream\":\"answered\"}");
                            }))
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
  void listen() throws Exception {
    RECEIVED.clear();
    Logger.getLogger(AuditLine.LOGGER).addHandler(capture);
    grant(table(System.currentTimeMillis()));
  }

  @AfterEach
  void stopListening() {
    Logger.getLogger(AuditLine.LOGGER).removeHandler(capture);
  }

  // --- the table ---------------------------------------------------------------------------------

  private GrantTableWire.GrantTable table(long version) {
    String target = "http://127.0.0.1:" + upstream.actualPort() + "/base";
    return new GrantTableWire.GrantTable(
        version,
        List.of(
            route("qits-edge", "suite", target, "SUITE_UPSTREAM", "header:X-Api-Key", "GET", "POST"),
            route("qits-edge", "suite-bearer", target, "SUITE_UPSTREAM", "bearer", "GET"),
            route("qits-edge", "unheld", target, "NOT_HELD", "bearer", "GET"),
            route("qits-edge", "self-check", "platform:projects", null, null, "GET"),
            route("qits-ci", "ci-only", target, "SUITE_UPSTREAM", "bearer", "GET")),
        List.of());
  }

  private static GrantTableWire.Route route(
      String application,
      String name,
      String target,
      String secret,
      String inject,
      String... methods) {
    return new GrantTableWire.Route(
        application, "dev", "2026.1201.101010", name, target, secret, inject, List.of(methods));
  }

  private void grant(GrantTableWire.GrantTable table) throws Exception {
    store.clear();
    store.store(table.version(), json.writeValueAsString(table), "application:qits-deployments");
    index.refresh();
  }

  // --- callers -----------------------------------------------------------------------------------

  private static String serviceToken(String clientId) {
    return MockIdp.ensureStarted()
        .token()
        .subject(clientId)
        .audience("qits-platform")
        .groups("clients/" + clientId, "qits:system")
        .mint();
  }

  private HttpResponse<String> call(String method, String path, String bearer, String... headers)
      throws Exception {
    HttpRequest.Builder request =
        HttpRequest.newBuilder(URI.create("http://127.0.0.1:" + proxy.port() + path))
            .method(
                method,
                method.equals("POST")
                    ? HttpRequest.BodyPublishers.ofString("{\"zone\":\"example\"}")
                    : HttpRequest.BodyPublishers.noBody());
    if (bearer != null) {
      request.header("Authorization", "Bearer " + bearer);
    }
    for (int i = 0; i < headers.length; i += 2) {
      request.header(headers[i], headers[i + 1]);
    }
    return http.send(request.build(), HttpResponse.BodyHandlers.ofString());
  }

  /** The one audit line of the call just made: it is written when the response ends. */
  private String theAuditLine() throws InterruptedException {
    long deadline = System.currentTimeMillis() + 5_000;
    while (audit.isEmpty() && System.currentTimeMillis() < deadline) {
      Thread.sleep(20);
    }
    Thread.sleep(100); // a second line, were there one, would be written by now
    assertEquals(1, audit.size(), "exactly one audit line per call: " + audit);
    String line = audit.get(0);
    audit.clear();
    return line;
  }

  // --- allowed -----------------------------------------------------------------------------------

  @Test
  void theSecretArrivesAndTheCallersCredentialsDoNot() throws Exception {
    String token = serviceToken(EDGE);
    HttpResponse<String> answer =
        call(
            "POST",
            "/suite/v1/zones/42?name=private-query-value",
            token,
            "Cookie",
            "session=caller-cookie-value",
            "X-Qits-Caller",
            "qits-edge",
            "X-Qits-Project",
            "qits",
            "X-Request-Note",
            "kept");
    assertEquals(200, answer.statusCode(), answer.body());
    assertEquals("{\"upstream\":\"answered\"}", answer.body());

    Received received = RECEIVED.poll(5, TimeUnit.SECONDS);
    assertNotNull(received, "the upstream was reached");
    assertEquals("POST", received.method());
    assertEquals("/base/v1/zones/42?name=private-query-value", received.uri());
    assertEquals("{\"zone\":\"example\"}", received.body(), "the body streams through");
    assertEquals(SECRET, received.headers().get("X-Api-Key"), "the secret is injected");
    assertNull(received.headers().get("Authorization"), "the caller's bearer stays behind");
    assertNull(received.headers().get("Cookie"), "the caller's cookie stays behind");
    assertNull(received.headers().get("X-Qits-Caller"));
    assertNull(received.headers().get("X-Qits-Project"));
    assertEquals("kept", received.headers().get("X-Request-Note"));
    assertEquals(
        "127.0.0.1:" + upstream.actualPort(),
        received.headers().get("Host"),
        "Host is the target's");

    String line = theAuditLine();
    assertTrue(
        line.startsWith(
            "egress decision=ALLOW principal=application:qits-edge route=suite method=POST"
                + " target=127.0.0.1 path=/base/v1/zones/42 status=200 durationMs="),
        line);
    assertTrue(line.endsWith(" reason=-"), line);
    for (String never :
        List.of(SECRET, "private-query-value", "caller-cookie-value", token, "name=")) {
      assertFalse(line.contains(never), "the audit line carries " + never + ": " + line);
    }
  }

  @Test
  void aBearerRouteReplacesTheCallersAuthorization() throws Exception {
    HttpResponse<String> answer = call("GET", "/suite-bearer/me", serviceToken(EDGE));
    assertEquals(200, answer.statusCode(), answer.body());
    Received received = RECEIVED.poll(5, TimeUnit.SECONDS);
    assertNotNull(received);
    assertEquals("/base/me", received.uri());
    assertEquals("Bearer " + SECRET, received.headers().get("Authorization"));
    assertTrue(theAuditLine().contains("decision=ALLOW"));
  }

  // --- refused -----------------------------------------------------------------------------------

  @Test
  void anUngrantedRouteIsForbidden() throws Exception {
    HttpResponse<String> answer = call("GET", "/ci-only/x?secret=1", serviceToken(EDGE));
    assertEquals(403, answer.statusCode());
    JsonObject body = new JsonObject(answer.body());
    assertEquals("no grant", body.getString("error"));
    assertEquals("application:qits-edge", body.getString("principal"));
    assertEquals("ci-only", body.getString("route"));
    assertEquals("GET", body.getString("method"));
    assertTrue(RECEIVED.isEmpty(), "nothing reached the upstream");
    String line = theAuditLine();
    assertTrue(
        line.startsWith(
            "egress decision=DENY principal=application:qits-edge route=ci-only method=GET"
                + " target=- path=/ci-only/x status=403"),
        line);
    assertTrue(line.endsWith(" reason=no-grant"), line);
  }

  @Test
  void aMethodOutsideTheRoutesMethodsIsForbidden() throws Exception {
    HttpResponse<String> answer = call("DELETE", "/suite/v1/zones/42", serviceToken(EDGE));
    assertEquals(403, answer.statusCode());
    assertEquals("DELETE", new JsonObject(answer.body()).getString("method"));
    assertTrue(RECEIVED.isEmpty());
    assertTrue(theAuditLine().endsWith(" reason=method-not-granted"));
  }

  @Test
  void anAgentHoldsNoRoute() throws Exception {
    String agent =
        MockIdp.ensureStarted()
            .token()
            .subject("tok-project-agent-qits-developer")
            .audience("qits-platform")
            .groups("qits:agent")
            .claim("agent", "developer")
            .claim("project", "qits")
            .mint();
    HttpResponse<String> answer = call("GET", "/suite/v1", agent);
    assertEquals(403, answer.statusCode());
    assertEquals("agent:developer", new JsonObject(answer.body()).getString("principal"));
    String line = theAuditLine();
    assertTrue(line.contains("decision=DENY principal=agent:developer route=suite"), line);
  }

  @Test
  void aServiceOfAnotherEnvironmentIsNoApplication() throws Exception {
    HttpResponse<String> answer = call("GET", "/suite/v1", serviceToken("prod-qits-edge"));
    assertEquals(403, answer.statusCode());
    assertEquals("subject:prod-qits-edge", new JsonObject(answer.body()).getString("principal"));
    theAuditLine();
  }

  @Test
  void noBearerIsUnauthenticated() throws Exception {
    HttpResponse<String> answer = call("GET", "/suite/v1", null);
    assertEquals(401, answer.statusCode());
    assertEquals(
        "Bearer realm=\"qits-egress\"",
        answer.headers().firstValue("WWW-Authenticate").orElse(null));
    assertNotNull(new JsonObject(answer.body()).getString("error"));
    String line = theAuditLine();
    assertTrue(line.contains("decision=DENY principal=- route=suite"), line);
    assertTrue(line.endsWith(" reason=no-credentials"), line);
  }

  @Test
  void aBadBearerIsUnauthenticated() throws Exception {
    MockIdp idp = MockIdp.ensureStarted();
    for (String bad :
        List.of(
            "not-a-jwt",
            idp.token().subject(EDGE).audience("qits-platform").signedByUnknownKey().mint(),
            idp.token().subject(EDGE).audience("somebody-else").mint())) {
      HttpResponse<String> answer = call("GET", "/suite/v1", bad);
      assertEquals(401, answer.statusCode(), bad);
      assertTrue(theAuditLine().endsWith(" reason=bad-credentials"));
    }
    assertTrue(RECEIVED.isEmpty());
  }

  @Test
  void noTableRefusesEveryCall() throws Exception {
    store.clear();
    index.refresh();
    HttpResponse<String> answer = call("GET", "/suite/v1", serviceToken(EDGE));
    assertEquals(503, answer.statusCode());
    assertEquals("no grant table yet", new JsonObject(answer.body()).getString("error"));
    assertTrue(RECEIVED.isEmpty());
    String line = theAuditLine();
    assertTrue(line.contains("decision=DENY principal=application:qits-edge"), line);
    assertTrue(line.endsWith(" reason=no-table"), line);
  }

  @Test
  void aSecretThisProcessDoesNotHoldIsABadGateway() throws Exception {
    HttpResponse<String> answer = call("GET", "/unheld/v1", serviceToken(EDGE));
    assertEquals(502, answer.statusCode());
    assertEquals("{\"error\":\"secret not configured\"}", answer.body());
    assertTrue(RECEIVED.isEmpty());
    assertTrue(theAuditLine().endsWith(" reason=no-secret"));
  }

  @Test
  void aPlatformRouteIsNotServedYet() throws Exception {
    HttpResponse<String> answer = call("GET", "/self-check/projects/api/projects", serviceToken(EDGE));
    assertEquals(501, answer.statusCode());
    assertEquals("platform routes not yet supported", new JsonObject(answer.body()).getString("error"));
    assertTrue(theAuditLine().endsWith(" reason=platform-route"));
  }

  @Test
  void dotSegmentsCannotLeaveTheBasePath() throws Exception {
    HttpResponse<String> answer = call("GET", "/suite/v1/%2e%2e/admin", serviceToken(EDGE));
    assertEquals(400, answer.statusCode());
    assertTrue(RECEIVED.isEmpty());
    assertTrue(theAuditLine().endsWith(" reason=bad-path"));
  }

  // --- opaque tokens -----------------------------------------------------------------------------

  @Test
  void anOpaqueTokenIsIntrospectedOnceThenBelieved() throws Exception {
    SuiteIdp.answer(
        200,
        new JsonObject().put("accessToken", serviceToken(EDGE)).put("expiresIn", 300).encode());
    int before = SuiteIdp.introspections();
    String opaque = "qits_tok_suiteAcceptedToken0000000000000000000000000";

    assertEquals(200, call("GET", "/suite-bearer/one", opaque).statusCode());
    assertTrue(theAuditLine().contains("decision=ALLOW principal=application:qits-edge"));
    assertEquals(200, call("GET", "/suite-bearer/two", opaque).statusCode());
    theAuditLine();

    assertEquals(before + 1, SuiteIdp.introspections(), "one introspection for two calls");
    String basic =
        "Basic "
            + Base64.getEncoder()
                .encodeToString(
                    "dev-qits-egress:suite-egress-secret".getBytes(StandardCharsets.UTF_8));
    assertEquals(basic, SuiteIdp.lastAuthorization(), "asked with this service's own client");
    Received first = RECEIVED.poll(5, TimeUnit.SECONDS);
    assertNotNull(first);
    assertEquals("Bearer " + SECRET, first.headers().get("Authorization"));
  }

  @Test
  void aTokenTheIdpRefusesIsUnauthenticated() throws Exception {
    SuiteIdp.answer(404, "{\"error\":\"not_found\"}");
    HttpResponse<String> answer =
        call("GET", "/suite/v1", "qits_tok_suiteRefusedToken00000000000000000000000000");
    assertEquals(401, answer.statusCode());
    assertTrue(theAuditLine().endsWith(" reason=bad-credentials"));
    assertTrue(RECEIVED.isEmpty());
  }
}
