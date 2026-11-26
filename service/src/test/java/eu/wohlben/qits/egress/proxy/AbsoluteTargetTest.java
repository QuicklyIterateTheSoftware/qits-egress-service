package eu.wohlben.qits.egress.proxy;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import eu.wohlben.qits.egress.api.GrantTableWire;
import eu.wohlben.qits.egress.identity.Principal;
import eu.wohlben.qits.egress.grants.GrantIndex;
import eu.wohlben.qits.egress.grants.GrantRoute;
import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.Collection;
import java.util.List;
import org.junit.jupiter.api.Test;

/** The HTTPS_PROXY forms alone: the credential, the absolute target and its match, CONNECT's authority. */
class AbsoluteTargetTest {

  static final Collection<GrantRoute> ROUTES =
      GrantIndex.index(
              new GrantTableWire.GrantTable(
                  1,
                  List.of(
                      route("hetzner", "https://api.hetzner.cloud/v1", "GET"),
                      route("hetzner-dns", "https://api.hetzner.cloud/v1/dns", "GET"),
                      route("other", "https://api.example:8443", "GET"),
                      route("self-check", "platform:projects", "GET")),
                  List.of()),
              false,
              "https://{label}.qits.wohlben.eu")
          .routes(new Principal(Principal.APPLICATION, "qits-edge"));

  static GrantTableWire.Route route(String name, String target, String... methods) {
    return new GrantTableWire.Route(
        "qits-edge", "dev", "1", name, target, name.equals("self-check") ? null : "KEY", name.equals("self-check") ? null : "bearer", List.of(methods));
  }

  private static String matched(String uri) {
    GrantRoute route = AbsoluteTarget.parse(uri).match(ROUTES);
    return route == null ? null : route.name();
  }

  @Test
  void theLongestBasePathOfTheSameOriginWins() {
    assertEquals("hetzner", matched("https://api.hetzner.cloud/v1/zones"));
    assertEquals("hetzner", matched("https://API.Hetzner.cloud:443/v1"));
    assertEquals("hetzner-dns", matched("https://api.hetzner.cloud/v1/dns/records?x=1"));
    assertNull(matched("https://api.hetzner.cloud/v2/zones"), "outside every base path");
    assertNull(matched("https://api.hetzner.cloud/v1x"), "a prefix is a whole segment");
    assertNull(matched("https://api.hetzner.cloud:8443/v1/zones"), "another port");
    assertNull(matched("https://evil.example/v1/zones"));
  }

  @Test
  void plainHttpOnTheDefaultPortReachesAnHttpsRoute() {
    assertEquals("hetzner", matched("http://api.hetzner.cloud/v1/zones"));
    assertNull(matched("http://api.hetzner.cloud:8080/v1/zones"));
    assertNull(matched("http://api.example:8443/x"), "only 80 stands for 443");
  }

  @Test
  void aPlatformRouteMatchesItsPlatformOrigin() {
    assertEquals("self-check", matched("https://projects.qits.wohlben.eu/projects/api/projects"));
    assertNull(matched("https://ci.qits.wohlben.eu/ci/api/runs"));
  }

  @Test
  void theTargetIsParsedWithItsDefaults() {
    AbsoluteTarget target = AbsoluteTarget.parse("http://Example.test?q=1");
    assertEquals(new AbsoluteTarget("http", "example.test", 80, "/", "q=1"), target);
    assertEquals("http://example.test", target.origin());
    assertNull(AbsoluteTarget.parse("http://user:pw@example.test/"));
    assertNull(AbsoluteTarget.parse("ftp://example.test/"));
    assertTrue(AbsoluteTarget.isAbsolute("HTTPS://example.test/"));
    assertFalse(AbsoluteTarget.isAbsolute("/hetzner/v1"));
  }

  @Test
  void theProxyCredentialIsTheBasicPasswordOrTheBearer() {
    String basic =
        "Basic " + Base64.getEncoder().encodeToString("anyone:the-token".getBytes(StandardCharsets.UTF_8));
    assertEquals("Bearer the-token", ProxyCredential.bearer(basic));
    assertEquals("Bearer the-token", ProxyCredential.bearer("Bearer the-token"));
    assertNull(ProxyCredential.bearer(null));
    assertNull(ProxyCredential.bearer("Basic not-base64!"));
    assertNull(
        ProxyCredential.bearer(
            "Basic " + Base64.getEncoder().encodeToString("only-a-user".getBytes(StandardCharsets.UTF_8))));
    assertNull(ProxyCredential.bearer("Digest x"));
  }

  @Test
  void aConnectAuthorityDefaultsTo443() {
    assertEquals(new ConnectTunnel.Authority("api.example", 443), ConnectTunnel.Authority.parse("API.example"));
    assertEquals(new ConnectTunnel.Authority("api.example", 8443), ConnectTunnel.Authority.parse("api.example:8443"));
    assertEquals(new ConnectTunnel.Authority("::1", 443), ConnectTunnel.Authority.parse("[::1]:443"));
    assertNull(ConnectTunnel.Authority.parse("api.example:0"));
    assertNull(ConnectTunnel.Authority.parse("http://api.example/"));
    assertNull(ConnectTunnel.Authority.parse(""));
  }

  @Test
  void aTunnelReachesOnlyItsRoutesHostAndPortAndNeverAPlatformRoute() {
    ConnectTunnel.Authority hetzner = ConnectTunnel.Authority.parse("api.hetzner.cloud:443");
    assertTrue(ROUTES.stream().anyMatch(hetzner::reaches));
    ConnectTunnel.Authority platform = ConnectTunnel.Authority.parse("projects.qits.wohlben.eu:443");
    assertFalse(ROUTES.stream().anyMatch(platform::reaches));
  }
}
