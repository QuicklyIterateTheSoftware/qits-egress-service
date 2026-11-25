package eu.wohlben.qits.egress.tls;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import eu.wohlben.qits.egress.api.GrantTableWire;
import eu.wohlben.qits.egress.grants.GrantIndex;
import java.time.Duration;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.CompletionStage;
import java.util.concurrent.atomic.AtomicReference;
import org.junit.jupiter.api.Test;

/**
 * The self-check's schedule, with fakes for the anchors door, the probe and the clock: when it runs,
 * what it logs, its backoff, and the re-check when the anchors move. The probe itself runs against
 * the real listeners in {@code EgressInterceptionTest}.
 */
class TlsSelfCheckTest {

  static final TlsSelfCheck.Target TARGET = new TlsSelfCheck.Target("api.hetzner.cloud", 443);

  /** The scheduled tasks, run by hand; their delays recorded. */
  final List<Duration> delays = new ArrayList<>();

  final List<Runnable> due = new ArrayList<>();

  final List<String> ok = new ArrayList<>();

  final List<String> failed = new ArrayList<>();

  final AtomicReference<TlsSelfCheck.Anchors> published =
      new AtomicReference<>(new TlsSelfCheck.Anchors("v1", Map.of("ab12", "CN=qits platform CA dev 2026-11, O=qits")));

  final AtomicReference<CompletionStage<TlsSelfCheck.Outcome>> answer =
      new AtomicReference<>(
          CompletableFuture.completedFuture(
              new TlsSelfCheck.Outcome(502, "5eed", "CN=qits platform CA dev 2026-11, O=qits")));

  final List<TlsSelfCheck.Anchors> probedWith = new ArrayList<>();

  boolean leafHeld = true;

  final TlsSelfCheck.Runner runner =
      new TlsSelfCheck.Runner(
          () -> CompletableFuture.completedFuture(published.get()),
          (target, anchors) -> {
            probedWith.add(anchors);
            return answer.get();
          },
          host -> leafHeld,
          (delay, task) -> {
            delays.add(delay);
            due.add(task);
          },
          new TlsSelfCheck.Runner.Sink() {
            @Override
            public void ok(String line) {
              ok.add(line);
            }

            @Override
            public void failed(String line) {
              failed.add(line);
            }
          },
          Duration.ofSeconds(30),
          Duration.ofMinutes(10));

  void runDue() {
    List<Runnable> now = new ArrayList<>(due);
    due.clear();
    now.forEach(Runnable::run);
  }

  @Test
  void theFirstTableWithTheRouteRunsTheCheckOnceAndLogsOk() {
    runner.table(TARGET);
    runDue();
    assertEquals(
        List.of(
            "egress tls self-check ok host=api.hetzner.cloud leafSerial=5eed"
                + " issuer=CN=qits platform CA dev 2026-11, O=qits status=502"),
        ok);
    assertTrue(failed.isEmpty());
    // The same target again (another table, the route unchanged): nothing new.
    runner.table(TARGET);
    runDue();
    assertEquals(1, ok.size());
    assertEquals(1, probedWith.size());
  }

  @Test
  void itWaitsQuietlyForTheLeaf() {
    leafHeld = false;
    runner.table(TARGET);
    runDue();
    runDue();
    assertTrue(probedWith.isEmpty(), "no check before the leaf is held");
    assertEquals(TlsSelfCheck.LEAF_POLL, delays.get(delays.size() - 1));
    assertTrue(failed.isEmpty(), "waiting is not failing");
    leafHeld = true;
    runDue();
    assertEquals(1, ok.size());
  }

  @Test
  void aFailureIsAWarnAndRetriesWithABackoff() {
    answer.set(CompletableFuture.failedFuture(new TlsSelfCheck.CheckFailed("the handshake failed: x")));
    runner.table(TARGET);
    runDue();
    assertEquals(
        List.of(
            "egress tls self-check failed host=api.hetzner.cloud reason=the handshake failed: x"
                + " retryIn=PT30S"),
        failed);
    runDue();
    runDue();
    assertEquals(Duration.ofMinutes(2), delays.get(delays.size() - 1), "30 s, 1 min, 2 min");
    for (int i = 0; i < 10; i++) {
      runDue();
    }
    assertEquals(Duration.ofMinutes(10), delays.get(delays.size() - 1), "capped at 10 min");
    answer.set(
        CompletableFuture.completedFuture(new TlsSelfCheck.Outcome(200, "5eed", "CN=a")));
    runDue();
    assertEquals(1, ok.size());
    assertTrue(due.isEmpty(), "a good check schedules nothing more");
  }

  @Test
  void movedAnchorsCheckAgain() {
    runner.table(TARGET);
    runDue();
    assertEquals(1, ok.size());
    runner.anchorsTick();
    assertEquals(1, ok.size(), "the same version: nothing");
    published.set(new TlsSelfCheck.Anchors("v2", Map.of("cd34", "CN=next")));
    runner.anchorsTick();
    assertEquals(2, ok.size(), "a new version: checked again");
    assertEquals("v2", probedWith.get(1).version());
  }

  @Test
  void aTableWithoutTheRouteStopsIt() {
    leafHeld = false;
    runner.table(TARGET);
    runner.table(null);
    leafHeld = true;
    runDue();
    runDue();
    assertTrue(probedWith.isEmpty());
  }

  @Test
  void theTargetIsTheRouteGrantedToThisApplicationWithConnect() {
    GrantIndex.Table table =
        GrantIndex.index(
            new GrantTableWire.GrantTable(
                1L,
                List.of(
                    new GrantTableWire.Route(
                        "qits-egress", "dev", "1", TlsSelfCheck.ROUTE, "https://api.hetzner.cloud",
                        "HETZNER_DNS", "bearer", List.of("CONNECT", "HEAD")),
                    new GrantTableWire.Route(
                        "qits-edge", "dev", "1", TlsSelfCheck.ROUTE, "https://other.example",
                        "HETZNER_DNS", "bearer", List.of("CONNECT"))),
                List.of()),
            false,
            "https://{label}.qits.wohlben.eu");
    assertEquals(TARGET, TlsSelfCheck.target(table, "qits-egress"));
    assertNull(TlsSelfCheck.target(table, "qits-other"));
    assertNull(TlsSelfCheck.target(null, "qits-egress"));
  }

  @Test
  void theAnchorsFetchCarriesTheBearer() throws Exception {
    io.vertx.core.Vertx vertx = io.vertx.core.Vertx.vertx();
    try {
      AtomicReference<String> authorization = new AtomicReference<>();
      AtomicReference<String> accept = new AtomicReference<>();
      io.vertx.core.http.HttpServer server =
          vertx
              .createHttpServer()
              .requestHandler(
                  request -> {
                    authorization.set(request.getHeader("Authorization"));
                    accept.set(request.getHeader("Accept"));
                    request
                        .response()
                        .putHeader("Content-Type", "application/json")
                        .end(
                            "{\"version\":\"v1\",\"anchors\":[{\"subject\":\"CN=a\","
                                + "\"sha256\":\"ab12\"}]}");
                  })
              .listen(0, "127.0.0.1")
              .toCompletionStage()
              .toCompletableFuture()
              .get(10, java.util.concurrent.TimeUnit.SECONDS);
      TlsSelfCheck.Anchors anchors =
          TlsSelfCheck.anchors(
                  vertx.createHttpClient(),
                  "http://127.0.0.1:" + server.actualPort() + "/certificates/",
                  10_000,
                  "egress-own-token")
              .toCompletableFuture()
              .get(10, java.util.concurrent.TimeUnit.SECONDS);
      assertEquals("Bearer egress-own-token", authorization.get());
      assertEquals("application/json", accept.get());
      assertEquals(Map.of("ab12", "CN=a"), anchors.anchors());
    } finally {
      vertx.close().toCompletionStage().toCompletableFuture().get(10, java.util.concurrent.TimeUnit.SECONDS);
    }
  }

  @Test
  void theAnchorsAnswerIsReadForItsDigestsAndSubjects() {
    TlsSelfCheck.Anchors anchors =
        TlsSelfCheck.anchors(
            "{\"version\":\"31a1\",\"anchors\":[{\"id\":\"x\",\"status\":\"ACTIVE\","
                + "\"subject\":\"CN=qits platform CA dev 2026-11, O=qits\",\"sha256\":\"AC7B\"}]}");
    assertEquals("31a1", anchors.version());
    assertEquals(Map.of("ac7b", "CN=qits platform CA dev 2026-11, O=qits"), anchors.anchors());
    assertFalse(TlsSelfCheck.Runner.reason(new IllegalStateException("a\nb")).contains("\n"));
  }
}
