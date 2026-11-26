package eu.wohlben.qits.egress.contracts.consumer;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.fasterxml.jackson.databind.DeserializationFeature;
import com.fasterxml.jackson.databind.ObjectMapper;
import eu.wohlben.qits.egress.api.GrantTableWire;
import eu.wohlben.qits.egress.grants.GrantIndex;
import eu.wohlben.qits.egress.grants.GrantRoute;
import eu.wohlben.qits.egress.identity.Principal;
import eu.wohlben.qits.pact.consumer.GoldenMasters;
import org.junit.jupiter.api.Test;

/**
 * <b>What qits-deployments pushes, as its own golden masters record it</b>: the body of {@code GET
 * /deployments/api/egress-grants} is the table it {@code PUT}s here (its {@code EgressGrantPusher}),
 * so every recorded egress-grants state must bind to {@link GrantTableWire.GrantTable} and index
 * the way the proxy looks routes up. Not a pact: this service never calls qits-deployments (it is
 * pushed to), so the deployer's recordings are read directly, the pinned jar moved by maintenance's
 * bumps like any golden-master pin.
 */
class DeploymentsGrantTableTest {

  static final GoldenMasters DEPLOYMENTS =
      GoldenMasters.of("qits-deployments-service", "qits-deployments");

  static final String OPERATION = "getEgressGrants";

  /** Jackson as Quarkus configures it: an unknown field is no failure. */
  private static final ObjectMapper JSON =
      new ObjectMapper().configure(DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES, false);

  private static GrantIndex.Table indexed(String state) throws Exception {
    assertTrue(DEPLOYMENTS.recorded(state, OPERATION), state + " is recorded");
    GrantTableWire.GrantTable table =
        JSON.readValue(DEPLOYMENTS.body(state, OPERATION), GrantTableWire.GrantTable.class);
    return GrantIndex.index(table, false, "https://{label}.qits.wohlben.eu");
  }

  @Test
  void aProjectRouteIsHeldByItsProjectAndItsAgents() throws Exception {
    GrantIndex.Table table = indexed("an egress grant table with a project route");
    String project = "00000000-0000-4000-8000-000000000001";

    GrantRoute portal = table.route(new Principal(Principal.PROJECT, project), "portal");
    assertNotNull(portal);
    assertEquals("project:" + project, portal.principal());
    assertNull(portal.problem(), "the deployer's project route is servable here");
    assertEquals("Cookie", portal.injectHeader());
    assertEquals("sid=", portal.injectPrefix());
    assertEquals("PROJECT_CONTRACT_SESSION", portal.secret());
    assertEquals(
        portal, table.route(new Principal(Principal.AGENT, "any-agent", project), "portal"));
    assertNull(table.route(new Principal(Principal.AGENT, "any-agent", "another"), "portal"));

    GrantRoute hetzner = table.route(new Principal(Principal.APPLICATION, "qits-edge"), "hetzner");
    assertNotNull(hetzner, "the application route sits beside it");
    assertNull(hetzner.problem());
    assertNull(table.route(new Principal(Principal.PROJECT, project), "hetzner"));
  }

  @Test
  void anApplicationRouteIsHeldByItsApplication() throws Exception {
    GrantIndex.Table table = indexed("an egress grant table with one route");
    GrantRoute hetzner = table.route(new Principal(Principal.APPLICATION, "qits-edge"), "hetzner");
    assertNotNull(hetzner);
    assertEquals("application:qits-edge", hetzner.principal());
    assertNull(hetzner.problem());
  }

  @Test
  void anEmptyTableIndexesEmpty() throws Exception {
    assertTrue(indexed("an empty egress grant table").routes().isEmpty());
  }
}
