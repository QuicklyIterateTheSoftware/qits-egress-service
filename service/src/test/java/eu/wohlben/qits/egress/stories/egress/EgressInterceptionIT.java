package eu.wohlben.qits.egress.stories.egress;

import static io.restassured.RestAssured.given;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import eu.wohlben.qits.egress.support.SuiteTls;
import eu.wohlben.qits.egress.testdb.EmbeddedPg;
import eu.wohlben.qits.servicemock.idp.MockIdp;
import eu.wohlben.qits.userflows.Interactions;
import eu.wohlben.qits.userflows.UserStory;
import eu.wohlben.qits.userflows.UserStoryDescription;
import eu.wohlben.qits.userflows.report.ReportAssertions;
import eu.wohlben.qits.userflows.report.UserflowReport;
import io.quarkus.test.junit.QuarkusIntegrationTest;
import io.quarkus.test.junit.QuarkusTestProfile;
import io.quarkus.test.junit.TestProfile;
import io.vertx.core.Vertx;
import io.vertx.core.http.HttpServer;
import io.vertx.core.http.HttpServerOptions;
import io.vertx.core.json.JsonObject;
import io.vertx.core.net.KeyCertOptions;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.cert.X509Certificate;
import java.time.Duration;
import java.time.Instant;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicLong;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.Assumptions;
import org.junit.jupiter.api.Test;

/**
 * <b>TLS ended inside a {@code CONNECT} tunnel, in the PACKAGED service</b> (qits-2644), with {@code
 * curl -x} as the client: the leaf comes through the real {@code LeafDoor} from a fake
 * qits-certificates in this JVM that signs with {@link SuiteTls#LEAF} (the service's {@code qits}
 * client mints at the mock idp); the third party is a fake https upstream on {@code localhost} whose
 * certificate {@link SuiteTls#UPSTREAM} signed, trusted by the service only through {@code
 * qits.egress.test.upstream-trust}. curl trusts the leaf CA alone ({@code --cacert}).
 *
 * <p>Run with {@code ./mvnw verify -DskipITs=false}.
 */
@QuarkusIntegrationTest
@TestProfile(EgressInterceptionIT.Packaged.class)
public class EgressInterceptionIT {

  static final String CATEGORY = "egress";

  static final String SLUG =
      "a-client-behind-an-https-proxy-reaches-a-third-party-through-the-intercepted-tunnel";

  static final String SECRET = "interception-it-secret-value";

  static final String HOST = "localhost";

  /**
   * What the fake upstream received, as system properties: the profile that started it and the test
   * that asks may be two class loaders.
   */
  static final String RECEIVED_AUTHORIZATION = "qits.test.interception-it.received-authorization";

  static final String RECEIVED_PROXY_AUTHORIZATION =
      "qits.test.interception-it.received-proxy-authorization";

  static final AtomicLong SERIAL = new AtomicLong(0x17000);

  /** The fakes, started once per JVM by the profile, before the packaged process. */
  static Vertx fakes;

  static HttpServer certificates;

  static HttpServer upstream;

  public static class Packaged implements QuarkusTestProfile {

    @Override
    public Map<String, String> getConfigOverrides() {
      MockIdp idp = MockIdp.ensureStarted();
      // The service's `qits` client mints here; any token will do for the fake CA.
      idp.service()
          .stub(
              "POST",
              "/idp/token",
              Map.of("access_token", "it-egress-client-token", "token_type", "Bearer", "expires_in", 300));
      startTheFakes();
      Map<String, String> overrides = new LinkedHashMap<>();
      overrides.put("QITS_RESOURCE_DB_URL", databaseUrl());
      overrides.put("QITS_RESOURCE_DB_USERNAME", EmbeddedPg.USER);
      overrides.put("QITS_RESOURCE_DB_PASSWORD", EmbeddedPg.PASSWORD);
      overrides.put("qits.auth.machine.required", "true");
      overrides.put("quarkus.oidc.auth-server-url", idp.baseUrl());
      overrides.put("qits.egress.idp.url", idp.baseUrl());
      overrides.put("QITS_RESOURCE_IDP_CLIENT_SECRET", "it-egress-client-secret");
      overrides.put("qits.egress.proxy.port", String.valueOf(port("proxy")));
      overrides.put("qits.egress.tls.port", String.valueOf(port("tls")));
      overrides.put(
          "qits.egress.certificates-url",
          "http://127.0.0.1:" + System.getProperty(PORT_PREFIX + "certificates") + "/certificates");
      overrides.put(
          "qits.egress.test.upstream-trust", SuiteTls.ca(SuiteTls.UPSTREAM).pem().toString());
      overrides.put("QITS_EGRESS_SECRET_SUITE_UPSTREAM", SECRET);
      overrides.put("quarkus.otel.sdk.disabled", "true");
      overrides.put("quarkus.shutdown.delay", "0s");
      return overrides;
    }
  }

  static final String PORT_PREFIX = "qits.test.interception-it.";

  /** A free port, chosen once per JVM whichever loader asks. */
  static synchronized int port(String name) {
    String parked = System.getProperty(PORT_PREFIX + name);
    if (parked != null) {
      return Integer.parseInt(parked);
    }
    try (java.net.ServerSocket socket = new java.net.ServerSocket(0)) {
      int port = socket.getLocalPort();
      System.setProperty(PORT_PREFIX + name, String.valueOf(port));
      return port;
    } catch (java.io.IOException e) {
      throw new java.io.UncheckedIOException(e);
    }
  }

  static synchronized String databaseUrl() {
    String parked = System.getProperty(PORT_PREFIX + "db-url");
    if (parked != null) {
      return parked;
    }
    String url = EmbeddedPg.url("egress_interception_it");
    System.setProperty(PORT_PREFIX + "db-url", url);
    return url;
  }

  /** The fake qits-certificates and the fake third party, once per JVM. */
  static synchronized void startTheFakes() {
    if (fakes != null) {
      return;
    }
    try {
      fakes = Vertx.vertx();
      SuiteTls.Ca leafCa = SuiteTls.ca(SuiteTls.LEAF);
      certificates =
          fakes
              .createHttpServer()
              .requestHandler(
                  request ->
                      request
                          .body()
                          .onSuccess(
                              body -> {
                                try {
                                  String csr = new JsonObject(body.toString()).getString("csr");
                                  Instant now = Instant.now();
                                  X509Certificate leaf =
                                      leafCa.sign(
                                          csr,
                                          now.minus(Duration.ofHours(1)),
                                          now.plus(Duration.ofDays(7)),
                                          BigInteger.valueOf(SERIAL.incrementAndGet()));
                                  String chain =
                                      SuiteTls.pem(leaf) + SuiteTls.pem(leafCa.certificate());
                                  request
                                      .response()
                                      .setStatusCode(201)
                                      .putHeader("Content-Type", "application/json")
                                      .end(
                                          new JsonObject()
                                              .put("certificate", SuiteTls.pem(leaf))
                                              .put("chain", chain)
                                              .put("serial", leaf.getSerialNumber().toString(16))
                                              .put("notAfter", leaf.getNotAfter().toInstant().toString())
                                              .put("anchorId", "00000000-0000-4000-8000-000000000001")
                                              .encode());
                                } catch (Exception e) {
                                  request.response().setStatusCode(400).end("{\"error\":\"bad csr\"}");
                                }
                              }))
              .listen(0, "127.0.0.1")
              .toCompletionStage()
              .toCompletableFuture()
              .get(10, TimeUnit.SECONDS);
      System.setProperty(PORT_PREFIX + "certificates", String.valueOf(certificates.actualPort()));
      upstream =
          fakes
              .createHttpServer(
                  new HttpServerOptions()
                      .setSsl(true)
                      .setKeyCertOptions(
                          KeyCertOptions.wrap(SuiteTls.ca(SuiteTls.UPSTREAM).server(HOST))))
              .requestHandler(
                  request -> {
                    System.setProperty(
                        RECEIVED_AUTHORIZATION, String.valueOf(request.getHeader("Authorization")));
                    System.setProperty(
                        RECEIVED_PROXY_AUTHORIZATION,
                        String.valueOf(request.getHeader("Proxy-Authorization")));
                    request.response().putHeader("Content-Type", "text/plain").end("upstream answered");
                  })
              .listen(0, "127.0.0.1")
              .toCompletionStage()
              .toCompletableFuture()
              .get(10, TimeUnit.SECONDS);
      System.setProperty(PORT_PREFIX + "upstream", String.valueOf(upstream.actualPort()));
    } catch (Exception e) {
      throw new IllegalStateException("the interception IT's fakes did not start", e);
    }
  }

  @UserStory(
      value = "A client behind an HTTPS proxy reaches a third party through the intercepted tunnel",
      category = CATEGORY)
  @UserStoryDescription(
      """
      A platform application configured with HTTPS_PROXY opens a CONNECT tunnel to qits-egress for a
      third party its grant names. qits-egress ends the tunnel's TLS itself, with a leaf for that host
      certified by the platform CA (which the client trusts), so every request inside the tunnel is
      seen: the caller's credentials stay behind, the route's secret is injected, and the third party
      is dialled over TLS that qits-egress verifies.
      """)
  @Test
  void curlThroughTheInterceptedTunnel(Interactions story) throws Exception {
    Path curl = Path.of("/usr/bin/curl");
    Assumptions.assumeTrue(Files.isExecutable(curl), "no curl in this image");
    MockIdp idp = MockIdp.attach();
    int upstreamPort = Integer.parseInt(System.getProperty(PORT_PREFIX + "upstream"));
    String table =
        "{\"version\":1764061300000,\"routes\":[{\"application\":\"qits-edge\","
            + "\"environment\":\"dev\",\"deployedVersion\":\"2026.1201.101010\","
            + "\"name\":\"third-party\",\"target\":\"https://" + HOST + ":" + upstreamPort + "\","
            + "\"secret\":\"SUITE_UPSTREAM\",\"inject\":\"bearer\","
            + "\"methods\":[\"CONNECT\",\"GET\"]}],\"refused\":[]}";
    given()
        .header("Authorization", "Bearer " + serviceToken(idp, "dev-qits-deployments"))
        .contentType("application/json")
        .body(table)
        .put("/egress/api/grant-table")
        .then()
        .statusCode(204);
    story.note("qits-deployments pushes a table granting qits-edge CONNECT and GET to the third party").as("pushed");

    String token = serviceToken(idp, "dev-qits-edge");
    Process run =
        new ProcessBuilder(
                curl.toString(),
                "-sS",
                "--max-time",
                "30",
                "-x",
                "http://bearer:" + token + "@127.0.0.1:" + port("proxy"),
                "--cacert",
                SuiteTls.ca(SuiteTls.LEAF).pem().toString(),
                "https://" + HOST + ":" + upstreamPort + "/v1/curl")
            .redirectErrorStream(true)
            .start();
    String out = new String(run.getInputStream().readAllBytes(), StandardCharsets.UTF_8);
    assertTrue(run.waitFor(40, TimeUnit.SECONDS));
    assertEquals(0, run.exitValue(), out);
    assertEquals("upstream answered", out);
    story.note("curl -x through qits-egress, trusting only the platform CA, gets the answer").as("answered");

    assertEquals("Bearer " + SECRET, System.getProperty(RECEIVED_AUTHORIZATION));
    assertEquals("null", System.getProperty(RECEIVED_PROXY_AUTHORIZATION));
    story.note("the third party received the route's secret and none of the caller's credentials").as("injected");
  }

  private static String serviceToken(MockIdp idp, String clientId) {
    return idp.token()
        .subject(clientId)
        .audience("qits-platform")
        .groups("clients/" + clientId, "qits:system")
        .mint();
  }

  @AfterAll
  static void theStoryReportIsComplete() throws Exception {
    ReportAssertions.assertComplete(CATEGORY, SLUG, UserflowReport.PASSED);
    ReportAssertions.assertStepId(CATEGORY, SLUG, "injected");
  }
}
