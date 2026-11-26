package eu.wohlben.qits.egress.api;

import static io.restassured.RestAssured.given;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.nullValue;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;

import com.fasterxml.jackson.databind.ObjectMapper;
import eu.wohlben.qits.egress.claude.ClaudeCredentials;
import eu.wohlben.qits.egress.contracts.ProviderStates;
import eu.wohlben.qits.egress.store.ClaudeCredentialStore;
import eu.wohlben.qits.egress.support.ContractCallers;
import io.quarkus.test.junit.QuarkusTest;
import io.restassured.response.Response;
import jakarta.inject.Inject;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

/**
 * {@code PUT|GET /egress/api/claude-credential} (qits-2664): only the runner writes; adopt stores
 * only when nothing is held, replace always; a placeholder is no login; the status names every
 * fact but a token — and no body any door writes carries either held token.
 */
@QuarkusTest
class ClaudeCredentialDoorTest {

  static final String PATH = "/egress/api/claude-credential";

  static final String ACCESS = "sk-ant-oat01-door-access-4b1c";

  static final String REFRESH = "sk-ant-ort01-door-refresh-9e2a";

  @Inject ClaudeCredentialStore store;

  @Inject ClaudeCredentials credentials;

  @Inject ObjectMapper json;

  /** Every body a door answered in this test, swept for the tokens at the end. */
  private final List<String> bodies = new ArrayList<>();

  @BeforeEach
  void empty() {
    store.clear();
    credentials.reload();
    ProviderStates.grantRunner();
  }

  @AfterEach
  void noTokenInAnyBody() {
    for (String body : bodies) {
      assertFalse(body.contains(ACCESS), "a door body carries the access token: " + body);
      assertFalse(body.contains(REFRESH), "a door body carries the refresh token: " + body);
      assertFalse(body.contains("door-access"), body);
      assertFalse(body.contains("door-refresh"), body);
    }
    store.clear();
    credentials.reload();
  }

  private String login(String access, String refresh) throws Exception {
    return json.writeValueAsString(
        new ClaudeCredentialWire.ClaudeAiOauth(
            access,
            refresh,
            1796126400000L,
            null,
            List.of("user:inference", "user:profile"),
            "max",
            "tier-x"));
  }

  private Response put(String authorization, String mode, String body) {
    var request = given().contentType("application/json").body(body);
    if (authorization != null) {
      request = request.header("Authorization", authorization);
    }
    Response response =
        mode == null ? request.when().put(PATH) : request.when().put(PATH + "?mode=" + mode);
    bodies.add(response.asString());
    return response;
  }

  private Response get(String authorization) {
    var request = given();
    if (authorization != null) {
      request = request.header("Authorization", authorization);
    }
    Response response = request.when().get(PATH);
    bodies.add(response.asString());
    return response;
  }

  // --- who may write ----------------------------------------------------------------------------

  @Test
  void anAnonymousCallerIsUnauthenticated() throws Exception {
    put(null, "adopt", login(ACCESS, REFRESH)).then().statusCode(401);
    get(null).then().statusCode(401);
  }

  @Test
  void onlyTheRunnerWrites() throws Exception {
    for (String role : List.of("qits:agent", "qits:system", "qits:admin", "qits:desk-admin")) {
      put(ContractCallers.caller("someone", role), "replace", login(ACCESS, REFRESH))
          .then()
          .statusCode(403);
    }
    assertFalse(store.held().isPresent(), "nothing was stored");
  }

  // --- adopt and replace ------------------------------------------------------------------------

  @Test
  void adoptStoresWhenNothingIsHeldAndConflictsAfter() throws Exception {
    put(ProviderStates.RUNNER_BEARER, "adopt", login(ACCESS, REFRESH)).then().statusCode(204);
    ClaudeCredentialStore.Credential held = store.held().orElseThrow();
    assertEquals(ACCESS, held.accessToken());
    assertEquals(REFRESH, held.refreshToken());
    assertEquals(Instant.ofEpochMilli(1796126400000L), held.expiresAt());
    assertEquals("user:inference user:profile", held.scopes());
    assertEquals("hand-over " + ProviderStates.RUNNER, held.source());
    assertEquals(ACCESS, credentials.current().accessToken(), "this replica swaps it in at once");

    put(ProviderStates.RUNNER_BEARER, "adopt", login("sk-other-access", "sk-other-refresh"))
        .then()
        .statusCode(409)
        .body("held", equalTo(true));
    assertEquals(ACCESS, store.held().orElseThrow().accessToken(), "the first adoption stays");
  }

  @Test
  void replaceAlwaysStores() throws Exception {
    put(ProviderStates.RUNNER_BEARER, "adopt", login("sk-first-access", "sk-first-refresh"))
        .then()
        .statusCode(204);
    put(ProviderStates.RUNNER_BEARER, "replace", login(ACCESS, REFRESH)).then().statusCode(204);
    ClaudeCredentialStore.Credential held = store.held().orElseThrow();
    assertEquals(ACCESS, held.accessToken());
    assertEquals("sign-in " + ProviderStates.RUNNER, held.source());
    assertNull(held.lastRefreshError());
    assertEquals(REFRESH, credentials.current().refreshToken());
  }

  @Test
  void aPlaceholderOrAnIncompleteLoginIsRefused() throws Exception {
    put(ProviderStates.RUNNER_BEARER, "adopt", login(ClaudeCredentials.PLACEHOLDER, REFRESH))
        .then()
        .statusCode(400)
        .body("error", equalTo("the placeholder is not a login"));
    put(ProviderStates.RUNNER_BEARER, "replace", login(ACCESS, ClaudeCredentials.PLACEHOLDER))
        .then()
        .statusCode(400);
    put(ProviderStates.RUNNER_BEARER, "replace", login(ACCESS, null)).then().statusCode(400);
    put(ProviderStates.RUNNER_BEARER, "replace", "{\"accessToken\":\"" + ACCESS + "\"}")
        .then()
        .statusCode(400);
    put(ProviderStates.RUNNER_BEARER, null, login(ACCESS, REFRESH)).then().statusCode(400);
    put(ProviderStates.RUNNER_BEARER, "steal", login(ACCESS, REFRESH)).then().statusCode(400);
    assertFalse(store.held().isPresent());
  }

  // --- the status -------------------------------------------------------------------------------

  @Test
  void theStatusIsReadByAgentsServicesAdminsAndTheRunner() throws Exception {
    get(ContractCallers.caller("agent", "qits:agent"))
        .then()
        .statusCode(200)
        .body("held", equalTo(false))
        .body("expiresAt", nullValue());
    put(ProviderStates.RUNNER_BEARER, "adopt", login(ACCESS, REFRESH)).then().statusCode(204);
    for (String role : List.of("qits:agent", "qits:system", "qits:admin", "qits:target-runner")) {
      get(ContractCallers.caller("reader", role))
          .then()
          .statusCode(200)
          .body("held", equalTo(true))
          .body("expiresAt", equalTo("2026-12-01T12:00:00Z"))
          .body("scopes", equalTo(List.of("user:inference", "user:profile")))
          .body("subscriptionType", equalTo("max"))
          .body("rateLimitTier", equalTo("tier-x"))
          .body("source", equalTo("hand-over " + ProviderStates.RUNNER))
          .body("lastRefreshError", nullValue());
    }
    get(ContractCallers.caller("desk", "qits:desk-admin")).then().statusCode(403);
  }
}
