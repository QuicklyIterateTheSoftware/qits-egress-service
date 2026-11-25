package eu.wohlben.qits.egress.tls;

import static io.restassured.RestAssured.given;
import static org.junit.jupiter.api.Assertions.assertEquals;

import com.fasterxml.jackson.databind.ObjectMapper;
import eu.wohlben.qits.egress.contracts.ProviderStates;
import eu.wohlben.qits.egress.grants.GrantIndex;
import eu.wohlben.qits.egress.store.GrantTableStore;
import io.quarkus.test.junit.QuarkusTest;
import jakarta.inject.Inject;
import java.util.Set;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;

/**
 * The hook: a grant table pushed to this replica hands its https hosts to {@link LeafCertificates}
 * for pre-issue at once. (The suite holds no {@code qits} client, so the issuance itself fails to a
 * WARN without dialling; {@link LeafCertificatesTest} and {@link LeafDoorTest} cover the rest.)
 */
@QuarkusTest
class LeafWiringTest {

  @Inject GrantTableStore store;

  @Inject GrantIndex index;

  @Inject LeafCertificates leaves;

  @Inject ObjectMapper json;

  @AfterEach
  void empty() {
    store.clear();
    index.refresh();
  }

  @Test
  void aPushedTablesHttpsHostsArePreIssued() {
    store.clear();
    index.refresh();
    leaves.want(Set.of());
    ProviderStates.grantPublisher();
    given()
        .contentType("application/json")
        .header("Authorization", ProviderStates.PUBLISHER_BEARER)
        .body(ProviderStates.tableJson(json))
        .when()
        .put("/egress/api/grant-table")
        .then()
        .statusCode(204);
    assertEquals(Set.of("api.hetzner.cloud"), leaves.wanted());
  }
}
