package eu.wohlben.qits.egress.api;

import static io.restassured.RestAssured.given;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.notNullValue;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;

import com.fasterxml.jackson.databind.ObjectMapper;
import eu.wohlben.qits.egress.contracts.ProviderStates;
import eu.wohlben.qits.egress.grants.GrantIndex;
import eu.wohlben.qits.egress.store.GrantTableStore;
import eu.wohlben.qits.egress.support.ContractCallers;
import io.quarkus.test.junit.QuarkusTest;
import jakarta.inject.Inject;
import java.util.List;
import java.util.Set;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

/**
 * {@code PUT|GET /egress/api/grant-table}: who may push (qits-deployments' own client, and nobody
 * else — not even another {@code qits:system} service), who may read, and how versions move.
 */
@QuarkusTest
class GrantTableDoorTest {

  static final String PATH = "/egress/api/grant-table";

  @Inject GrantTableStore store;

  @Inject GrantIndex index;

  @Inject ObjectMapper json;

  @BeforeEach
  void empty() {
    store.clear();
    index.refresh();
    ProviderStates.grantPublisher();
  }

  private String table(long version) throws Exception {
    return json.writeValueAsString(
        new GrantTableWire.GrantTable(
            version, ProviderStates.TABLE.routes(), ProviderStates.TABLE.refused()));
  }

  private io.restassured.response.Response put(String authorization, String body) {
    var request = given().contentType("application/json").body(body);
    if (authorization != null) {
      request = request.header("Authorization", authorization);
    }
    return request.when().put(PATH);
  }

  // --- who may push ------------------------------------------------------------------------------

  @Test
  void anAnonymousCallerIsUnauthenticated() throws Exception {
    put(null, table(10)).then().statusCode(401);
    given().when().get(PATH).then().statusCode(401);
  }

  @Test
  void theDeployersOwnClientPushes() throws Exception {
    put(ProviderStates.PUBLISHER_BEARER, table(10)).then().statusCode(204);
    GrantTableStore.Held held = store.held().orElseThrow();
    assertEquals(10, held.version());
    assertEquals("application:qits-deployments", held.receivedFrom());
    assertEquals(10, index.current().version(), "the replica that took the push enforces it");
  }

  @Test
  void anotherSystemClientIsRefused() throws Exception {
    put(ContractCallers.client("dev-qits-edge"), table(10))
        .then()
        .statusCode(403)
        .body("error", equalTo(GrantTableResource.NOT_THE_PUBLISHER));
    given()
        .header("Authorization", ContractCallers.client("dev-qits-edge"))
        .when()
        .get(PATH)
        .then()
        .statusCode(403);
    assertEquals(java.util.Optional.empty(), store.held());
  }

  @Test
  void theDeployersSubjectWithoutItsClientGroupIsRefused() throws Exception {
    String forged = "Bearer suite-forged-deployer";
    ContractCallers.bearer(
        forged,
        ProviderStates.PUBLISHER,
        Set.of("qits:system"),
        Set.of("qits:system"));
    put(forged, table(10)).then().statusCode(403);
  }

  @Test
  void aSystemCallerWithNoTokenIsRefused() throws Exception {
    put(ContractCallers.caller(ProviderStates.PUBLISHER, Roles.SYSTEM), table(10))
        .then()
        .statusCode(403);
  }

  @Test
  void theDeployerInAnotherEnvironmentIsRefused() throws Exception {
    put(ContractCallers.client("prod-qits-deployments"), table(10)).then().statusCode(403);
  }

  @Test
  void anAdminOrAnAgentCannotPush() throws Exception {
    put(ContractCallers.caller("person", Roles.ADMIN), table(10)).then().statusCode(403);
    put(ContractCallers.caller("agent", Roles.AGENT), table(10)).then().statusCode(403);
  }

  // --- versions ----------------------------------------------------------------------------------

  @Test
  void theSameVersionIsIdempotentAndAnOlderOneConflicts() throws Exception {
    put(ProviderStates.PUBLISHER_BEARER, table(20)).then().statusCode(204);
    put(ProviderStates.PUBLISHER_BEARER, table(20)).then().statusCode(204);
    put(ProviderStates.PUBLISHER_BEARER, table(19))
        .then()
        .statusCode(409)
        .body("held", equalTo(20));
    put(ProviderStates.PUBLISHER_BEARER, table(21)).then().statusCode(204);
    assertEquals(21, store.held().orElseThrow().version());
    assertEquals(21, index.current().version());
  }

  @Test
  void aTableWithoutAVersionIsRefused() {
    put(ProviderStates.PUBLISHER_BEARER, "{\"routes\":[],\"refused\":[]}").then().statusCode(400);
  }

  // --- who may read ------------------------------------------------------------------------------

  @Test
  void noTableIsA404() {
    given()
        .header("Authorization", ProviderStates.PUBLISHER_BEARER)
        .when()
        .get(PATH)
        .then()
        .statusCode(404)
        .body("error", equalTo("no grant table is held"));
    assertNull(index.current());
  }

  @Test
  void theDeployerPeopleAndAgentsReadTheHeldTable() throws Exception {
    put(ProviderStates.PUBLISHER_BEARER, table(30)).then().statusCode(204);
    for (String reader :
        List.of(
            ProviderStates.PUBLISHER_BEARER,
            ContractCallers.caller("person", Roles.ADMIN),
            ContractCallers.caller("admin-agent", Roles.ADMIN_AGENT),
            ContractCallers.caller("desk", Roles.DESK_ADMIN),
            ContractCallers.caller("agent", Roles.AGENT))) {
      given()
          .header("Authorization", reader)
          .when()
          .get(PATH)
          .then()
          .statusCode(200)
          .body("version", equalTo(30))
          .body("receivedAt", notNullValue())
          .body("routes[0].name", equalTo("hetzner"))
          .body("routes[0].secret", equalTo("HETZNER_DNS"))
          .body("refused.size()", equalTo(0));
    }
  }
}
