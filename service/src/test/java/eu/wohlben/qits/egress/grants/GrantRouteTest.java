package eu.wohlben.qits.egress.grants;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import eu.wohlben.qits.egress.api.GrantTableWire;
import eu.wohlben.qits.egress.identity.Principal;
import java.util.List;
import java.util.Set;
import org.junit.jupiter.api.Test;

/** A pushed route compiled for the request path, and the index built from a table. */
class GrantRouteTest {

  private static GrantTableWire.Route route(String name, String target, String secret, String inject) {
    return new GrantTableWire.Route(
        "qits-edge", "dev", "1", name, target, secret, inject, List.of("get", "POST"));
  }

  @Test
  void anHttpsTargetCompiles() {
    GrantRoute route =
        GrantRoute.of(route("hetzner", "https://api.hetzner.cloud/v1/", "HETZNER_DNS", "bearer"), false);
    assertNull(route.problem());
    assertTrue(route.ssl());
    assertEquals("api.hetzner.cloud", route.host());
    assertEquals(-1, route.port());
    assertEquals(443, route.dialPort());
    assertEquals("/v1", route.basePath());
    assertEquals("Authorization", route.injectHeader());
    assertEquals("Bearer ", route.injectPrefix());
    assertEquals(Set.of("GET", "POST"), route.methods());
  }

  @Test
  void aHeaderInjectionNamesItsHeader() {
    GrantRoute route =
        GrantRoute.of(route("x", "https://h.example:8443", "KEY", "header:X-Api-Key"), false);
    assertNull(route.problem());
    assertEquals("X-Api-Key", route.injectHeader());
    assertEquals("", route.injectPrefix());
    assertEquals("h.example:8443", route.authority());
    assertEquals("", route.basePath());
  }

  @Test
  void plainHttpIsRefusedUnlessTheSuiteAllowsIt() {
    GrantTableWire.Route plain = route("x", "http://127.0.0.1:1/b", "KEY", "bearer");
    assertNotNull(GrantRoute.of(plain, false).problem());
    assertNull(GrantRoute.of(plain, true).problem());
  }

  @Test
  void badRoutesCarryTheirProblem() {
    assertNotNull(GrantRoute.of(route("x", "https://u:p@h.example", "KEY", "bearer"), false).problem());
    assertNotNull(GrantRoute.of(route("x", "https://h.example/?q=1", "KEY", "bearer"), false).problem());
    assertNotNull(GrantRoute.of(route("x", "https://h.example", "key", "bearer"), false).problem());
    assertNotNull(GrantRoute.of(route("x", "https://h.example", "KEY", "header:Bad Name"), false).problem());
    assertNotNull(GrantRoute.of(route("x", "https://h.example", "KEY", "basic"), false).problem());
  }

  @Test
  void aPlatformTargetKeepsItsLabel() {
    GrantRoute route = GrantRoute.of(route("self-check", "platform:projects", null, null), false);
    assertTrue(route.isPlatform());
    assertEquals("projects", route.platform());
    assertNull(route.problem());
    assertTrue(route.ssl());
    assertEquals("projects.qits.wohlben.eu", route.host());
    assertEquals(443, route.dialPort());
    assertEquals("", route.basePath());
  }

  @Test
  void aPlatformTargetIsThePlatformOriginOfItsLabel() {
    GrantRoute route =
        GrantRoute.of(
            route("self-check", "platform:idp", null, null), true, "http://127.0.0.1:9/{label}");
    assertEquals("127.0.0.1", route.host());
    assertEquals(9, route.dialPort());
    assertEquals("/idp", route.basePath());
    assertNull(route.targetProblem());
    assertNotNull(
        GrantRoute.of(route("x", "platform:Bad.Label", null, null), false).problem(),
        "a label is a plain DNS label");
  }

  @Test
  void aConnectOnlyRouteHasADiallableTarget() {
    GrantRoute route = GrantRoute.of(route("registry", "https://registry.example", null, null), false);
    assertNotNull(route.problem(), "no secret, no injection: not servable as a call");
    assertNull(route.targetProblem(), "but a tunnel needs only the target");
  }

  @Test
  void theIndexIsByPrincipalAndNameAndKeepsTheFirstDuplicate() {
    GrantTableWire.GrantTable table =
        new GrantTableWire.GrantTable(
            7,
            List.of(
                route("hetzner", "https://first.example", "A", "bearer"),
                route("hetzner", "https://second.example", "B", "bearer"),
                new GrantTableWire.Route(
                    "qits-ci", "dev", "1", "hetzner", "https://ci.example", "C", "bearer", List.of("GET"))),
            List.of());
    GrantIndex.Table index = GrantIndex.index(table, false);
    assertEquals(7, index.version());
    assertEquals("first.example", index.route(app("qits-edge"), "hetzner").host());
    assertEquals("ci.example", index.route(app("qits-ci"), "hetzner").host());
    assertNull(index.route(app("qits-deployments"), "hetzner"));
    assertNull(index.route(null, "hetzner"));
  }

  private static Principal app(String application) {
    return new Principal(Principal.APPLICATION, application);
  }

  private static GrantTableWire.Route projectRoute(String project, String name, String target) {
    return new GrantTableWire.Route(
        "project:" + project, null, null, "0f1e2d3c4b5a", name, target, "PROJECT_P_SESSION",
        "cookie:sid", List.of("GET"));
  }

  @Test
  void aCookieInjectionIsTheCookieHeaderWithTheName() {
    GrantRoute route = GrantRoute.of(route("portal", "https://portal.example", "KEY", "cookie:sid"), false);
    assertNull(route.problem());
    assertEquals("Cookie", route.injectHeader());
    assertEquals("sid=", route.injectPrefix());
    assertNull(GrantRoute.of(route("x", "https://h.example", "KEY", "cookie:__Host-a.b~c"), false).problem());
    assertNotNull(GrantRoute.of(route("x", "https://h.example", "KEY", "cookie:"), false).problem());
    assertNotNull(GrantRoute.of(route("x", "https://h.example", "KEY", "cookie:a=b"), false).problem());
    assertNotNull(GrantRoute.of(route("x", "https://h.example", "KEY", "cookie:a b"), false).problem());
    assertNotNull(
        GrantRoute.of(route("x", "https://h.example", "KEY", "cookie:" + "a".repeat(65)), false).problem());
  }

  @Test
  void aResolvedProjectSecretNameIsServable() {
    String longest = "PROJECT_" + "P".repeat(63) + "_" + "N".repeat(64);
    assertNull(GrantRoute.of(route("x", "https://h.example", longest, "bearer"), false).problem());
    assertNotNull(GrantRoute.of(route("x", "https://h.example", longest + "X", "bearer"), false).problem());
  }

  @Test
  void aRouteOfATableWithoutPrincipalIsItsApplications() {
    GrantTableWire.Route old = route("hetzner", "https://api.hetzner.cloud", "HETZNER_DNS", "bearer");
    assertEquals("application:qits-edge", old.principal());
    assertEquals("application:qits-edge", GrantRoute.of(old, false).principal());
    assertEquals("application:qits-edge", new GrantTableWire.Refused("qits-edge", "1", "bad").principal());
    assertNull(new GrantTableWire.Refused(null, null, "1", "bad").principal());
    assertEquals(
        "project:p", new GrantTableWire.Refused("project:p", null, "abc", "bad").principal());
  }

  @Test
  void anAgentHoldsItsOwnRoutesThenItsProjects() {
    GrantTableWire.GrantTable table =
        new GrantTableWire.GrantTable(
            9,
            List.of(
                projectRoute("p", "portal", "https://portal.example"),
                projectRoute("p", "shared", "https://project.example"),
                projectRoute("q", "other", "https://q.example"),
                new GrantTableWire.Route(
                    "agent:a1", null, null, "1", "shared", "https://agent.example", "S", "bearer",
                    List.of("GET"))),
            List.of());
    GrantIndex.Table index = GrantIndex.index(table, false);
    Principal agent = new Principal(Principal.AGENT, "a1", "p");
    Principal project = new Principal(Principal.PROJECT, "p");
    Principal stranger = new Principal(Principal.AGENT, "a2", "q");

    assertEquals(List.of("agent:a1", "project:p"), GrantIndex.Table.holders(agent));
    assertEquals(List.of("project:p"), GrantIndex.Table.holders(project));
    assertEquals(List.of("agent:a9"), GrantIndex.Table.holders(new Principal(Principal.AGENT, "a9", null)));
    assertEquals(List.of(), GrantIndex.Table.holders(null));

    assertEquals("portal.example", index.route(agent, "portal").host());
    assertEquals("agent.example", index.route(agent, "shared").host(), "its own route first");
    assertEquals("project.example", index.route(project, "shared").host());
    assertNull(index.route(stranger, "portal"), "another project's agent");
    assertNull(index.route(app("p"), "portal"), "an application is never a project");
    assertEquals(
        Set.of("portal.example", "agent.example"),
        index.routes(agent).stream().map(GrantRoute::host).collect(java.util.stream.Collectors.toSet()));
    assertEquals(
        Set.of("q.example"),
        index.routes(stranger).stream().map(GrantRoute::host).collect(java.util.stream.Collectors.toSet()));
    assertTrue(index.routes(new Principal(Principal.AGENT, "a9", null)).isEmpty());
  }
}
