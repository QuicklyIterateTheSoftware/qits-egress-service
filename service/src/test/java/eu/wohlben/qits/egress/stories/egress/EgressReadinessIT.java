package eu.wohlben.qits.egress.stories.egress;

import static io.restassured.RestAssured.given;
import static org.hamcrest.Matchers.equalTo;
import static org.junit.jupiter.api.Assertions.assertTrue;

import eu.wohlben.qits.egress.testdb.EmbeddedPg;
import eu.wohlben.qits.servicemock.idp.MockIdp;
import eu.wohlben.qits.userflows.Interactions;
import eu.wohlben.qits.userflows.NetworkCapture;
import eu.wohlben.qits.userflows.NetworkEdge;
import eu.wohlben.qits.userflows.NetworkTaps;
import eu.wohlben.qits.userflows.UserStory;
import eu.wohlben.qits.userflows.UserStoryDescription;
import eu.wohlben.qits.userflows.report.ReportAssertions;
import eu.wohlben.qits.userflows.report.UserflowReport;
import io.quarkus.test.junit.QuarkusIntegrationTest;
import io.quarkus.test.junit.QuarkusTestProfile;
import io.quarkus.test.junit.TestProfile;
import java.util.LinkedHashMap;
import java.util.Map;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

/**
 * The service as it is <b>packaged</b>, with the OIDC tenant <b>on</b> against {@link MockIdp} —
 * the shipped validation block (discovery, JWKS, audience {@code qits-platform}) that no {@code
 * @QuarkusTest} here exercises, since every suite turns the gate off.
 *
 * <p>It is also this repository's <b>userflow catalogue</b>: the story's documentation, with an
 * observed network diagram, is written under {@code service/target/userstories/}, which the
 * java-service release recipe publishes as {@code @userflows/qits-egress}.
 *
 * <p>Run with {@code ./mvnw verify -DskipITs=false}.
 */
@QuarkusIntegrationTest
@TestProfile(EgressReadinessIT.PackagedWithMockIdp.class)
public class EgressReadinessIT {

  static final String CATEGORY = "egress";

  static final String READY_SLUG = "the-deployer-finds-qits-egress-ready";

  static final String SERVICE = "qits-egress";

  static final String ENFORCED_SLUG = "qits-deployments-pushes-the-grant-table-and-the-gateway-enforces-it";

  /**
   * The packaged process's environment: the {@code QITS_RESOURCE_DB_*} triple on this JVM's
   * embedded postgres, the gate on, the idp moved to the mock, telemetry dark and no shutdown delay.
   * Every key is a RUNTIME key: a packaged artifact takes its configuration as {@code -D} arguments.
   */
  public static class PackagedWithMockIdp implements QuarkusTestProfile {

    static final String URL_PROPERTY = "qits.test.userflow-it.db-url";

    @Override
    public Map<String, String> getConfigOverrides() {
      MockIdp idp = MockIdp.ensureStarted();
      Map<String, String> overrides = new LinkedHashMap<>();
      overrides.put("QITS_RESOURCE_DB_URL", databaseUrl());
      overrides.put("QITS_RESOURCE_DB_USERNAME", EmbeddedPg.USER);
      overrides.put("QITS_RESOURCE_DB_PASSWORD", EmbeddedPg.PASSWORD);
      overrides.put("qits.auth.machine.required", "true");
      overrides.put("quarkus.oidc.auth-server-url", idp.baseUrl());
      // The proxy listener's own validation (discovery, JWKS) reads the same mock, on a free port.
      overrides.put("qits.egress.idp.url", idp.baseUrl());
      overrides.put("qits.egress.proxy.port", String.valueOf(proxyPort()));
      // The loopback interception listener (qits-2644) on a free port, never the host's 8443.
      overrides.put("qits.egress.tls.port", "0");
      overrides.put("quarkus.otel.sdk.disabled", "true");
      overrides.put("quarkus.shutdown.delay", "0s");
      return overrides;
    }

    static final String PROXY_PORT_PROPERTY = "qits.test.userflow-it.proxy-port";

    /** The proxy listener's port: chosen free once per JVM, whichever loader asks. */
    static synchronized int proxyPort() {
      String parked = System.getProperty(PROXY_PORT_PROPERTY);
      if (parked != null) {
        return Integer.parseInt(parked);
      }
      try (java.net.ServerSocket socket = new java.net.ServerSocket(0)) {
        int port = socket.getLocalPort();
        System.setProperty(PROXY_PORT_PROPERTY, String.valueOf(port));
        return port;
      } catch (java.io.IOException e) {
        throw new java.io.UncheckedIOException(e);
      }
    }

    /** One url per JVM, parked in a system property for the other classloaders. */
    static synchronized String databaseUrl() {
      String recorded = System.getProperty(URL_PROPERTY);
      if (recorded != null) {
        return recorded;
      }
      String url = EmbeddedPg.url("egress_userflow_it");
      System.setProperty(URL_PROPERTY, url);
      return url;
    }
  }

  @BeforeAll
  static void tapBothEndsOfTheNetwork() {
    NetworkTaps.restAssured(SERVICE);
    NetworkCapture.source(
        "mock-idp",
        () ->
            MockIdp.attach().recordedRequests().stream()
                .map(
                    request ->
                        NetworkEdge.http(
                            SERVICE,
                            MockIdp.SERVICE_NAME,
                            request.method() + " " + request.path() + " -> " + request.status()))
                .toList());
  }

  @UserStory(value = "The deployer finds qits-egress ready", category = CATEGORY)
  @UserStoryDescription(
      """
      qits-deployments starts each of qits-egress' two replicas and gates the rollout on
      /egress/q/health/ready. The replica migrates its store (the table qits-deployments pushes its
      grant table into), fetches qits-idp's signing keys so it can tell its callers apart, and
      answers ready. Readiness does not wait for a grant table: until one is pushed, the proxy
      refuses every call, and the first deployment can still pass its gate.
      """)
  @Test
  void theDeployerFindsTheServiceReady(Interactions story) {
    MockIdp idp = MockIdp.attach();
    story.note("qits-egress starts with the OIDC tenant on, beside a reachable qits-idp");

    given()
        .get("/egress/q/health/ready")
        .then()
        .statusCode(200)
        .body("status", equalTo("UP"));
    story.note("the readiness probe answers UP").as("ready");

    assertTrue(
        idp.recordedRequests().stream().anyMatch(r -> "/idp/jwks".equals(r.path())),
        "the packaged service never fetched /idp/jwks at startup");
    story.note("the signing keys were fetched at startup").as("jwks-fetched");
  }

  @UserStory(
      value = "qits-deployments pushes the grant table and the gateway enforces it",
      category = CATEGORY)
  @UserStoryDescription(
      """
      Until qits-deployments pushes a grant table, the gateway refuses every call with 503. The push
      (PUT /egress/api/grant-table) is admitted for the deployer's own service client only: another
      platform service holding qits:system is refused. Once a table is held, a caller the table
      grants nothing to, such as an agent, is refused with 403, and the gateway never dials out.
      """)
  @Test
  void theDeployerPushesAndTheGatewayEnforces(Interactions story) {
    MockIdp idp = MockIdp.attach();
    String agent =
        idp.token()
            .subject("tok-project-agent-qits-developer")
            .audience("qits-platform")
            .groups("qits:agent")
            .claim("agent", "developer")
            .mint();

    given()
        .port(PackagedWithMockIdp.proxyPort())
        .header("Authorization", "Bearer " + agent)
        .get("/hetzner/v1/zones")
        .then()
        .statusCode(503)
        .body("error", equalTo("no grant table yet"));
    story.note("before any push, the gateway answers 503 no grant table yet").as("no-table");

    String table =
        "{\"version\":1764061200000,\"routes\":[{\"application\":\"qits-edge\","
            + "\"environment\":\"dev\",\"deployedVersion\":\"2026.1201.101010\","
            + "\"name\":\"hetzner\",\"target\":\"https://api.hetzner.cloud\","
            + "\"secret\":\"HETZNER_DNS\",\"inject\":\"bearer\","
            + "\"methods\":[\"GET\",\"POST\"]}],\"refused\":[]}";
    given()
        .header("Authorization", "Bearer " + serviceToken(idp, "dev-qits-edge"))
        .contentType("application/json")
        .body(table)
        .put("/egress/api/grant-table")
        .then()
        .statusCode(403);
    story.note("another platform service's client cannot push a table").as("foreign-refused");

    given()
        .header("Authorization", "Bearer " + serviceToken(idp, "dev-qits-deployments"))
        .contentType("application/json")
        .body(table)
        .put("/egress/api/grant-table")
        .then()
        .statusCode(204);
    story.note("qits-deployments' own client pushes the table").as("pushed");

    given()
        .port(PackagedWithMockIdp.proxyPort())
        .header("Authorization", "Bearer " + agent)
        .get("/hetzner/v1/zones")
        .then()
        .statusCode(403)
        .body("error", equalTo("no grant"))
        .body("principal", equalTo("agent:developer"));
    story.note("an agent holds no route: 403 no grant").as("agent-refused");
  }

  /** A platform service's own client token, as qits-idp mints it. */
  private static String serviceToken(MockIdp idp, String clientId) {
    return idp.token()
        .subject(clientId)
        .audience("qits-platform")
        .groups("clients/" + clientId, "qits:system")
        .mint();
  }

  @AfterAll
  static void theStoryReportIsComplete() {
    ReportAssertions.assertComplete(CATEGORY, READY_SLUG, UserflowReport.PASSED);
    ReportAssertions.assertEdge(
        CATEGORY, READY_SLUG, "http", SERVICE, MockIdp.SERVICE_NAME, "GET /idp/jwks -> 200");
    ReportAssertions.assertStepId(CATEGORY, READY_SLUG, "jwks-fetched");
    ReportAssertions.assertComplete(CATEGORY, ENFORCED_SLUG, UserflowReport.PASSED);
    ReportAssertions.assertStepId(CATEGORY, ENFORCED_SLUG, "agent-refused");
  }
}
