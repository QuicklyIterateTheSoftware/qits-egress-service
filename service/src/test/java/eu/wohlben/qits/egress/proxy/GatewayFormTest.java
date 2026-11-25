package eu.wohlben.qits.egress.proxy;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import io.vertx.core.MultiMap;
import org.junit.jupiter.api.Test;

/** The gateway form's parsing, the outbound strip and the audit line's safe alphabet, alone. */
class GatewayFormTest {

  @Test
  void theFirstSegmentIsTheRoute() {
    assertEquals(new EgressProxy.Gateway("hetzner", "/v1/zones"), EgressProxy.Gateway.parse("/hetzner/v1/zones"));
    assertEquals(new EgressProxy.Gateway("hetzner", ""), EgressProxy.Gateway.parse("/hetzner"));
    assertEquals(new EgressProxy.Gateway("hetzner", "/"), EgressProxy.Gateway.parse("/hetzner/"));
    assertNull(EgressProxy.Gateway.parse("/"));
    assertNull(EgressProxy.Gateway.parse("/Hetzner/x"));
    assertNull(EgressProxy.Gateway.parse("/%2e%2e/x"));
    assertNull(EgressProxy.Gateway.parse("relative"));
  }

  @Test
  void dotSegmentsAreUnsafe() {
    assertTrue(EgressProxy.Gateway.safe("/v1/zones"));
    assertTrue(EgressProxy.Gateway.safe(""));
    assertTrue(EgressProxy.Gateway.safe("/a..b/"));
    assertFalse(EgressProxy.Gateway.safe("/v1/../admin"));
    assertFalse(EgressProxy.Gateway.safe("/v1/./x"));
    assertFalse(EgressProxy.Gateway.safe("/v1/%2E%2e/x"));
  }

  @Test
  void theUpstreamPathIsNeverEmpty() {
    assertEquals("/", EgressProxy.upstreamPath("", ""));
    assertEquals("/v1", EgressProxy.upstreamPath("/v1", ""));
    assertEquals("/v1/zones", EgressProxy.upstreamPath("/v1", "/zones"));
  }

  @Test
  void theCallersCredentialsAndPlatformHeadersAreStripped() {
    MultiMap headers = MultiMap.caseInsensitiveMultiMap();
    headers.add("Authorization", "Bearer caller");
    headers.add("proxy-authorization", "Basic x");
    headers.add("Cookie", "a=b");
    headers.add("X-Qits-Caller", "qits-edge");
    headers.add("x-qits-project", "qits");
    headers.add("Host", "dev-qits-egress:8081");
    headers.add("Accept", "application/json");
    EgressOutbound.strip(headers);
    assertEquals(1, headers.size(), headers.toString());
    assertEquals("application/json", headers.get("Accept"));
  }

  @Test
  void anAuditValueCannotForgeAKeyOrALine() {
    assertEquals("-", AuditLine.clean(null));
    assertEquals("/a_b_reason_ALLOW_x", AuditLine.clean("/a b reason=ALLOW\nx"));
    assertEquals("application:qits-edge", AuditLine.clean("application:qits-edge"));
  }
}
