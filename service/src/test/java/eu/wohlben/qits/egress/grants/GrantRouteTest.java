package eu.wohlben.qits.egress.grants;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import eu.wohlben.qits.egress.api.GrantTableWire;
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
  void theIndexIsByApplicationAndNameAndKeepsTheFirstDuplicate() {
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
    assertEquals("first.example", index.route("qits-edge", "hetzner").host());
    assertEquals("ci.example", index.route("qits-ci", "hetzner").host());
    assertNull(index.route("qits-deployments", "hetzner"));
    assertNull(index.route(null, "hetzner"));
  }
}
