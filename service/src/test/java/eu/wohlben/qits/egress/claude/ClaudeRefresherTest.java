package eu.wohlben.qits.egress.claude;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import eu.wohlben.qits.egress.store.ClaudeCredentialStore;
import eu.wohlben.qits.egress.store.ClaudeCredentialStore.Refreshed;
import io.quarkus.test.junit.QuarkusTest;
import io.vertx.core.Vertx;
import io.vertx.core.http.HttpClient;
import io.vertx.core.http.HttpClientOptions;
import io.vertx.core.http.HttpServer;
import io.vertx.core.json.JsonObject;
import jakarta.inject.Inject;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.List;
import java.util.Set;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.logging.Handler;
import java.util.logging.LogRecord;
import java.util.logging.Logger;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

/**
 * <b>One replica refreshes</b> (qits-2664): two {@link ClaudeRefresher}s — two replicas, each with
 * its own client — over the one database, racing a due refresh against a fake token endpoint, make
 * exactly one call, and both then read the rotated pair. Not due: no call. A refusal: {@code
 * last_refresh_error} and a WARN, neither carrying the body the endpoint answered.
 */
@QuarkusTest
class ClaudeRefresherTest {

  static final String OLD_ACCESS = "sk-ant-oat01-old-access";

  static final String OLD_REFRESH = "sk-ant-ort01-old-refresh";

  static final String NEW_ACCESS = "sk-ant-oat01-rotated-access";

  static final String NEW_REFRESH = "sk-ant-ort01-rotated-refresh";

  static final String CLIENT_ID = "9d1c250a-e61b-44d9-88ed-5944d1962f5e";

  static Vertx fake;

  static HttpServer endpoint;

  static final AtomicInteger CALLS = new AtomicInteger();

  static final List<JsonObject> BODIES = new CopyOnWriteArrayList<>();

  /** 200 with the rotated pair, or this status with a body echoing the old token. */
  static volatile int answer = 200;

  @Inject Vertx vertx;

  @Inject ClaudeCredentialStore store;

  @BeforeAll
  static void startTheEndpoint() throws Exception {
    fake = Vertx.vertx();
    endpoint =
        fake.createHttpServer()
            .requestHandler(
                request ->
                    request
                        .body()
                        .onSuccess(
                            body -> {
                              CALLS.incrementAndGet();
                              BODIES.add(new JsonObject(body.toString()));
                              // Slow enough that the second replica asks while the first holds
                              // the lock.
                              fake.setTimer(
                                  300,
                                  id -> {
                                    if (answer != 200) {
                                      request
                                          .response()
                                          .setStatusCode(answer)
                                          .putHeader("Content-Type", "application/json")
                                          .end(
                                              "{\"error\":\"invalid_grant\",\"echo\":\""
                                                  + OLD_REFRESH
                                                  + "\"}");
                                      return;
                                    }
                                    request
                                        .response()
                                        .putHeader("Content-Type", "application/json")
                                        .end(
                                            new JsonObject()
                                                .put("token_type", "Bearer")
                                                .put("access_token", NEW_ACCESS)
                                                .put("refresh_token", NEW_REFRESH)
                                                .put("expires_in", 28800)
                                                .put("scope", "user:inference user:profile")
                                                .encode());
                                  });
                            }))
            .listen(0, "127.0.0.1")
            .toCompletionStage()
            .toCompletableFuture()
            .get(10, TimeUnit.SECONDS);
  }

  @AfterAll
  static void stopTheEndpoint() throws Exception {
    fake.close().toCompletionStage().toCompletableFuture().get(10, TimeUnit.SECONDS);
  }

  @BeforeEach
  void holdALoginDueForRefresh() {
    CALLS.set(0);
    BODIES.clear();
    answer = 200;
    store.clear();
    store.replace(login(Instant.now().plus(Duration.ofMinutes(10))));
  }

  @AfterEach
  void forget() {
    store.clear();
  }

  private static ClaudeCredentialStore.Login login(Instant expiresAt) {
    return new ClaudeCredentialStore.Login(
        OLD_ACCESS, OLD_REFRESH, expiresAt, null, "user:inference", "max", "tier", "hand-over t");
  }

  /** One replica: its own client and endpoint, the shared database. */
  private ClaudeRefresher replica(HttpClient client) {
    return new ClaudeRefresher(
        store,
        new ClaudeTokenEndpoint(
            client, "http://127.0.0.1:" + endpoint.actualPort() + "/v1/oauth/token", CLIENT_ID, 5_000),
        Duration.ofMinutes(60),
        Clock.systemUTC());
  }

  @Test
  void twoReplicasRacingMakeOneCallAndBothSeeTheRotatedPair() throws Exception {
    HttpClient one = vertx.createHttpClient(new HttpClientOptions());
    HttpClient two = vertx.createHttpClient(new HttpClientOptions());
    ExecutorService threads = Executors.newFixedThreadPool(2);
    try {
      ClaudeRefresher first = replica(one);
      ClaudeRefresher second = replica(two);
      CountDownLatch start = new CountDownLatch(1);
      Future<Seen> a = threads.submit(() -> seen(start, first));
      Future<Seen> b = threads.submit(() -> seen(start, second));
      start.countDown();
      Seen seenByA = a.get(30, TimeUnit.SECONDS);
      Seen seenByB = b.get(30, TimeUnit.SECONDS);

      assertEquals(1, CALLS.get(), "exactly one replica called the token endpoint");
      assertEquals(
          Set.of(Refreshed.ROTATED, Refreshed.NOT_DUE),
          Set.of(seenByA.outcome(), seenByB.outcome()),
          "one rotated, the other found it no longer due");
      for (Seen seen : List.of(seenByA, seenByB)) {
        assertEquals(NEW_ACCESS, seen.held().accessToken());
        assertEquals(NEW_REFRESH, seen.held().refreshToken());
      }
      ClaudeCredentialStore.Credential held = store.held().orElseThrow();
      assertEquals("user:inference user:profile", held.scopes());
      assertTrue(held.expiresAt().isAfter(Instant.now().plus(Duration.ofHours(7))), "now + 8 h");
      assertTrue(held.lastRefreshAt() != null);
      assertNull(held.lastRefreshError());

      JsonObject sent = BODIES.get(0);
      assertEquals("refresh_token", sent.getString("grant_type"));
      assertEquals(OLD_REFRESH, sent.getString("refresh_token"));
      assertEquals(CLIENT_ID, sent.getString("client_id"));
    } finally {
      threads.shutdownNow();
      one.close();
      two.close();
    }
  }

  record Seen(Refreshed outcome, ClaudeCredentialStore.Credential held) {}

  private Seen seen(CountDownLatch start, ClaudeRefresher replica) throws InterruptedException {
    start.await();
    Refreshed outcome = replica.refreshIfDue();
    return new Seen(outcome, store.held().orElseThrow());
  }

  @Test
  void aLoginWithMoreThanTheMarginLeftIsNotRefreshed() {
    store.replace(login(Instant.now().plus(Duration.ofHours(5))));
    HttpClient client = vertx.createHttpClient(new HttpClientOptions());
    try {
      assertEquals(Refreshed.NOT_DUE, replica(client).refreshIfDue());
      assertEquals(0, CALLS.get());
      assertEquals(OLD_ACCESS, store.held().orElseThrow().accessToken());
    } finally {
      client.close();
    }
  }

  @Test
  void nothingHeldCallsNothing() {
    store.clear();
    HttpClient client = vertx.createHttpClient(new HttpClientOptions());
    try {
      assertEquals(Refreshed.NOT_HELD, replica(client).refreshIfDue());
      assertEquals(0, CALLS.get());
    } finally {
      client.close();
    }
  }

  @Test
  void aRefusalIsRecordedWithoutTheBody() throws Exception {
    answer = 400;
    List<String> warnings = new CopyOnWriteArrayList<>();
    Handler capture =
        new Handler() {
          @Override
          public void publish(LogRecord record) {
            warnings.add(String.valueOf(record.getMessage()) + " " + List.of(params(record)));
          }

          @Override
          public void flush() {}

          @Override
          public void close() {}
        };
    Logger logger = Logger.getLogger(ClaudeRefresher.class.getName());
    logger.addHandler(capture);
    HttpClient client = vertx.createHttpClient(new HttpClientOptions());
    try {
      assertEquals(Refreshed.FAILED, replica(client).refreshIfDue());
      ClaudeCredentialStore.Credential held = store.held().orElseThrow();
      assertEquals("the token endpoint answered 400", held.lastRefreshError());
      assertEquals(OLD_ACCESS, held.accessToken(), "the held pair stays");
      assertEquals(OLD_REFRESH, held.refreshToken());
      assertFalse(warnings.isEmpty(), "a WARN");
      for (String line : warnings) {
        assertFalse(line.contains(OLD_REFRESH), line);
        assertFalse(line.contains("invalid_grant"), line);
      }
    } finally {
      logger.removeHandler(capture);
      client.close();
    }
  }

  private static Object[] params(LogRecord record) {
    return record.getParameters() == null ? new Object[0] : record.getParameters();
  }

  @Test
  void anUnreachableEndpointIsAFixedReason() {
    HttpClient client = vertx.createHttpClient(new HttpClientOptions());
    try {
      ClaudeRefresher replica =
          new ClaudeRefresher(
              store,
              new ClaudeTokenEndpoint(client, "http://127.0.0.1:1/v1/oauth/token", CLIENT_ID, 2_000),
              Duration.ofMinutes(60),
              Clock.systemUTC());
      assertEquals(Refreshed.FAILED, replica.refreshIfDue());
      assertTrue(
          store.held().orElseThrow().lastRefreshError().startsWith("the token endpoint cannot be reached"),
          store.held().orElseThrow().lastRefreshError());
    } finally {
      client.close();
    }
  }

  @Test
  void anAnswerWithoutATokenIsAFailure() {
    assertFalse(
        ClaudeTokenEndpoint.rotation(new ClaudeTokenEndpoint.Answer(200, "{}"), Instant.now())
            .succeeded());
    assertFalse(
        ClaudeTokenEndpoint.rotation(new ClaudeTokenEndpoint.Answer(200, "[]"), Instant.now())
            .succeeded());
    assertTrue(
        ClaudeTokenEndpoint.rotation(
                new ClaudeTokenEndpoint.Answer(
                    200, "{\"access_token\":\"a\",\"expires_in\":60}"),
                Instant.now())
            .succeeded());
  }
}
