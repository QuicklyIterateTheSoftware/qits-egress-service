package eu.wohlben.qits.egress.tls;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import eu.wohlben.qits.egress.api.GrantTableWire;
import eu.wohlben.qits.egress.grants.GrantIndex;
import eu.wohlben.qits.egress.grants.GrantRoute;
import java.security.cert.X509Certificate;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneId;
import java.time.ZoneOffset;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.CompletionStage;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;
import org.junit.jupiter.api.Test;

/**
 * {@link LeafCertificates} against an issuer the test completes by hand and a clock it moves:
 * pre-issue, the concurrency bound, renewal at two thirds, backoff, the old leaf kept, inline.
 */
class LeafCertificatesTest {

  static final Instant T0 = Instant.parse("2026-11-25T12:00:00Z");

  static final Duration LIFE = Duration.ofDays(7);

  /** A clock the test moves. */
  static final class MovingClock extends Clock {
    Instant now = T0;

    void advance(Duration by) {
      now = now.plus(by);
    }

    @Override
    public ZoneId getZone() {
      return ZoneOffset.UTC;
    }

    @Override
    public Clock withZone(ZoneId zone) {
      return this;
    }

    @Override
    public Instant instant() {
      return now;
    }
  }

  /** Every issuance asked, completed by the test. */
  static final class HandIssuer implements LeafIssuer {
    record Asked(String host, CompletableFuture<Leaf> answer) {}

    final List<Asked> asked = new ArrayList<>();

    @Override
    public synchronized CompletionStage<Leaf> issue(String host) {
      CompletableFuture<Leaf> answer = new CompletableFuture<>();
      asked.add(new Asked(host, answer));
      return answer;
    }

    synchronized List<String> hosts() {
      return asked.stream().map(Asked::host).toList();
    }

    synchronized Asked last() {
      return asked.get(asked.size() - 1);
    }

    synchronized Asked of(String host) {
      return asked.stream().filter(a -> a.host().equals(host)).reduce((a, b) -> b).orElseThrow();
    }
  }

  final MovingClock clock = new MovingClock();

  final HandIssuer issuer = new HandIssuer();

  final LeafCertificates leaves =
      new LeafCertificates(issuer, clock, LeafCertificates.Settings.defaults());

  static Leaf leaf(String host, Instant notBefore, String serial) {
    return new Leaf(
        host, null, new X509Certificate[] {null}, serial, notBefore, notBefore.plus(LIFE), "anchor");
  }

  Leaf issueAndComplete(String host, String serial) {
    leaves.want(Set.of(host));
    Leaf leaf = leaf(host, clock.instant(), serial);
    issuer.of(host).answer().complete(leaf);
    return leaf;
  }

  static GrantRoute route(String application, String name, String host, boolean ssl, String platform, String problem) {
    return new GrantRoute(
        application, name, Set.of("GET"), platform, ssl, host, -1, "", "S", "Authorization", "Bearer ", problem, null);
  }

  // --- pre-issue ---------------------------------------------------------------------------------

  @Test
  void onlyHttpsHostsOfTheTableAreCoveredEachOnce() {
    GrantIndex.Table table =
        new GrantIndex.Table(
            7,
            Map.of(
                "application:qits-edge",
                Map.of(
                    "hetzner", route("qits-edge", "hetzner", "api.hetzner.cloud", true, null, null),
                    "plain", route("qits-edge", "plain", "plain.example.org", false, null, null),
                    "idp", route("qits-edge", "idp", null, true, "idp", null),
                    "broken", route("qits-edge", "broken", "broken.example.org", true, null, "the injection is neither")),
                "application:qits-ci",
                Map.of(
                    "hetzner", route("qits-ci", "hetzner", "API.Hetzner.Cloud", true, null, null),
                    "github", route("qits-ci", "github", "api.github.com", true, null, null))));

    assertEquals(Set.of("api.github.com", "api.hetzner.cloud"), LeafCertificates.httpsHosts(table));

    leaves.want(LeafCertificates.httpsHosts(table));
    assertEquals(List.of("api.github.com", "api.hetzner.cloud"), issuer.hosts());
  }

  @Test
  void aProjectRouteHostIsPreIssuedFromTheIndexedTable() {
    GrantIndex.Table table =
        GrantIndex.index(
            new GrantTableWire.GrantTable(
                3,
                List.of(
                    new GrantTableWire.Route(
                        "project:p", null, null, "0f1e2d3c4b5a", "portal", "https://Portal.Example.com",
                        "PROJECT_P_SESSION", "cookie:sid", List.of("GET")),
                    new GrantTableWire.Route(
                        "qits-edge", "dev", "1", "hetzner", "https://api.hetzner.cloud", "HETZNER_DNS",
                        "bearer", List.of("GET"))),
                List.of()),
            false,
            "https://{label}.qits.wohlben.eu");

    assertEquals(Set.of("api.hetzner.cloud", "portal.example.com"), LeafCertificates.httpsHosts(table));
  }

  @Test
  void atMostFourAreIssuedAtOnce() {
    leaves.want(Set.of("a.example.org", "b.example.org", "c.example.org", "d.example.org", "e.example.org", "f.example.org"));
    assertEquals(4, issuer.hosts().size());

    leaves.tick();
    assertEquals(4, issuer.hosts().size(), "a tick starts nothing while four are in flight");

    issuer.asked.get(0).answer().complete(leaf(issuer.asked.get(0).host(), T0, "1"));
    assertEquals(5, issuer.hosts().size(), "a finished one makes room for the next");

    issuer.asked.get(1).answer().completeExceptionally(new LeafIssueFailed(503, "down"));
    assertEquals(6, issuer.hosts().size(), "so does a failed one");
    assertEquals(6, Set.copyOf(issuer.hosts()).size(), "each host once");
  }

  @Test
  void aHostWithAValidLeafIsNotIssuedAgain() {
    issueAndComplete("api.example.org", "1");
    leaves.want(Set.of("api.example.org"));
    leaves.tick();
    assertEquals(1, issuer.hosts().size());
    assertEquals("1", leaves.leafFor("API.example.org").orElseThrow().serial());
  }

  // --- renewal -----------------------------------------------------------------------------------

  @Test
  void aLeafIsRenewedAtTwoThirdsOfItsLife() {
    Leaf first = issueAndComplete("api.example.org", "1");
    Instant renewAt = first.renewAt(2.0 / 3.0);
    assertEquals(T0.plus(LIFE.multipliedBy(2).dividedBy(3)), renewAt);

    clock.now = renewAt.minusSeconds(1);
    leaves.tick();
    assertEquals(1, issuer.hosts().size(), "not before two thirds");

    clock.now = renewAt;
    leaves.tick();
    assertEquals(2, issuer.hosts().size(), "renewed at two thirds");

    Leaf second = leaf("api.example.org", clock.instant(), "2");
    issuer.last().answer().complete(second);
    assertSame(second, leaves.leafFor("api.example.org").orElseThrow());
  }

  @Test
  void aFailedRenewalKeepsServingTheOldLeafUntilItExpires() {
    Leaf first = issueAndComplete("api.example.org", "1");
    clock.now = first.renewAt(2.0 / 3.0);
    leaves.tick();
    issuer.last().answer().completeExceptionally(new LeafIssueFailed(503, "unavailable"));

    assertSame(first, leaves.leafFor("api.example.org").orElseThrow(), "the old leaf is served");

    clock.now = first.notAfter();
    assertTrue(leaves.leafFor("api.example.org").isEmpty(), "but never past its notAfter");
  }

  @Test
  void failuresBackOffFromThirtySecondsToTenMinutes() {
    leaves.want(Set.of("api.example.org"));
    List<Duration> waits = new ArrayList<>();
    for (int failure = 1; failure <= 7; failure++) {
      assertEquals(failure, issuer.hosts().size());
      issuer.last().answer().completeExceptionally(new LeafIssueFailed(503, "unavailable"));
      Instant retryAt = leaves.retryAt("api.example.org").orElseThrow();
      waits.add(Duration.between(clock.instant(), retryAt));

      clock.now = retryAt.minusSeconds(1);
      leaves.tick();
      assertEquals(failure, issuer.hosts().size(), "nothing before the backoff ends");
      clock.now = retryAt;
      leaves.tick();
    }
    assertEquals(
        List.of(
            Duration.ofSeconds(30),
            Duration.ofSeconds(60),
            Duration.ofSeconds(120),
            Duration.ofSeconds(240),
            Duration.ofSeconds(480),
            Duration.ofMinutes(10),
            Duration.ofMinutes(10)),
        waits);

    issuer.last().answer().complete(leaf("api.example.org", clock.instant(), "1"));
    assertTrue(leaves.retryAt("api.example.org").isEmpty(), "a success clears the backoff");
  }

  @Test
  void anExpiredLeafIsDroppedAndAWantedHostIssuedAgain() {
    Leaf first = issueAndComplete("api.example.org", "1");
    clock.now = first.renewAt(2.0 / 3.0);
    leaves.tick();
    issuer.last().answer().completeExceptionally(new LeafIssueFailed(503, "unavailable"));
    clock.now = first.notAfter();
    leaves.tick();
    assertTrue(leaves.leafFor("api.example.org").isEmpty());
    assertEquals(3, issuer.hosts().size(), "the backoff ran out long ago: issued again");
  }

  @Test
  void aHostNoLongerWantedIsNotRenewed() {
    Leaf first = issueAndComplete("api.example.org", "1");
    leaves.want(Set.of());
    clock.now = first.renewAt(2.0 / 3.0);
    leaves.tick();
    assertEquals(1, issuer.hosts().size());
    assertSame(first, leaves.leafFor("api.example.org").orElseThrow(), "kept until it expires");
  }

  // --- inline ------------------------------------------------------------------------------------

  @Test
  void issueNowAnswersTheHeldLeaf() throws Exception {
    Leaf first = issueAndComplete("api.example.org", "1");
    assertSame(first, leaves.issueNow("api.example.org").toCompletableFuture().get(1, TimeUnit.SECONDS));
    assertEquals(1, issuer.hosts().size());
  }

  @Test
  void issueNowIssuesAtOnceOutsideTheQueue() throws Exception {
    leaves.want(Set.of("a.example.org", "b.example.org", "c.example.org", "d.example.org"));
    assertEquals(4, issuer.hosts().size());

    CompletableFuture<Leaf> inline = leaves.issueNow("new.example.org").toCompletableFuture();
    assertEquals("new.example.org", issuer.last().host(), "not queued behind the four");
    Leaf leaf = leaf("new.example.org", T0, "9");
    issuer.last().answer().complete(leaf);
    assertSame(leaf, inline.get(1, TimeUnit.SECONDS));
    assertSame(leaf, leaves.leafFor("new.example.org").orElseThrow());
  }

  @Test
  void issueNowJoinsAnIssuanceInFlight() throws Exception {
    leaves.want(Set.of("api.example.org"));
    CompletableFuture<Leaf> inline = leaves.issueNow("api.example.org").toCompletableFuture();
    assertEquals(1, issuer.hosts().size(), "one issuance, shared");
    Leaf leaf = leaf("api.example.org", T0, "1");
    issuer.last().answer().complete(leaf);
    assertSame(leaf, inline.get(1, TimeUnit.SECONDS));
  }

  @Test
  void issueNowTimesOut() {
    LeafCertificates quick =
        new LeafCertificates(
            issuer,
            clock,
            new LeafCertificates.Settings(
                2.0 / 3.0, 4, Duration.ofSeconds(30), Duration.ofMinutes(10), Duration.ofMillis(200)));
    ExecutionException failed =
        assertThrows(
            ExecutionException.class,
            () -> quick.issueNow("slow.example.org").toCompletableFuture().get(5, TimeUnit.SECONDS));
    assertInstanceOf(TimeoutException.class, failed.getCause());

    // The issuance carries on and its leaf is kept when it comes.
    Leaf leaf = leaf("slow.example.org", T0, "1");
    issuer.last().answer().complete(leaf);
    assertSame(leaf, quick.leafFor("slow.example.org").orElseThrow());
  }

  @Test
  void anInlineFailureFailsTheCallerAndBacksOff() {
    CompletableFuture<Leaf> inline = leaves.issueNow("api.example.org").toCompletableFuture();
    issuer.last().answer().completeExceptionally(new LeafIssueFailed(503, "unavailable"));
    ExecutionException failed = assertThrows(ExecutionException.class, () -> inline.get(1, TimeUnit.SECONDS));
    assertInstanceOf(LeafIssueFailed.class, failed.getCause());
    assertEquals(clock.instant().plusSeconds(30), leaves.retryAt("api.example.org").orElseThrow());
  }
}
