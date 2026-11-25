package eu.wohlben.qits.egress.identity;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;

import io.vertx.core.json.JsonArray;
import io.vertx.core.json.JsonObject;
import org.junit.jupiter.api.Test;

/** The principal mapping: only a service's own client token, in this environment, is an application. */
class PrincipalTest {

  private static JsonObject claims(String sub, String... groups) {
    return new JsonObject().put("sub", sub).put("groups", new JsonArray(java.util.List.of((Object[]) groups)));
  }

  @Test
  void aServiceClientIsItsApplication() {
    Principal principal =
        Principal.of(claims("dev-qits-edge", "clients/dev-qits-edge", "qits:system"), "dev");
    assertEquals("application:qits-edge", principal.toString());
    assertEquals("qits-edge", principal.application());
  }

  @Test
  void eachHalfOfTheClientRuleIsNeeded() {
    assertEquals(
        "subject:dev-qits-edge",
        Principal.of(claims("dev-qits-edge", "qits:system"), "dev").toString());
    assertEquals(
        "subject:dev-qits-edge",
        Principal.of(claims("dev-qits-edge", "clients/dev-qits-edge"), "dev").toString());
    assertEquals(
        "subject:prod-qits-edge",
        Principal.of(claims("prod-qits-edge", "clients/prod-qits-edge", "qits:system"), "dev")
            .toString());
    assertEquals("subject:dev-", Principal.of(claims("dev-", "clients/dev-", "qits:system"), "dev").toString());
  }

  @Test
  void otherwiseAgentThenProjectThenSubject() {
    JsonObject agent = claims("tok-x", "qits:agent").put("agent", "developer").put("project", "qits");
    assertEquals("agent:developer", Principal.of(agent, "dev").toString());
    assertNull(Principal.of(agent, "dev").application());
    JsonObject project = claims("tok-y").put("project", "qits");
    assertEquals("project:qits", Principal.of(project, "dev").toString());
    assertEquals("subject:person", Principal.of(claims("person"), "dev").toString());
    assertEquals("subject:-", Principal.of(new JsonObject(), "dev").toString());
  }
}
