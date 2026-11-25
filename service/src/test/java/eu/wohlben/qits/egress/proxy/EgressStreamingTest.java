package eu.wohlben.qits.egress.proxy;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.fasterxml.jackson.databind.ObjectMapper;
import eu.wohlben.qits.egress.api.GrantTableWire;
import eu.wohlben.qits.egress.grants.GrantIndex;
import eu.wohlben.qits.egress.store.GrantTableStore;
import eu.wohlben.qits.servicemock.idp.MockIdp;
import io.quarkus.test.junit.QuarkusTest;
import io.vertx.core.MultiMap;
import io.vertx.core.Vertx;
import io.vertx.core.http.HttpMethod;
import io.vertx.core.http.HttpServer;
import io.vertx.core.http.HttpServerResponse;
import io.vertx.core.http.WebSocket;
import io.vertx.core.http.WebSocketConnectOptions;
import jakarta.inject.Inject;
import java.io.IOException;
import java.io.InputStream;
import java.net.URI;
import java.net.URLEncoder;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.Base64;
import java.util.List;
import java.util.concurrent.BlockingQueue;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.LinkedBlockingQueue;
import java.util.concurrent.TimeUnit;
import java.util.logging.Handler;
import java.util.logging.LogRecord;
import java.util.logging.Logger;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

/**
 * <b>Streams, WebSockets, scrubbing and the drain</b> (qits-2621), through the real listener against
 * a fake upstream on plain http that answers in deliberately awkward shapes: a secret split across
 * two chunks, a redirect carrying it, an event stream with a gap, a slow answer, a WebSocket echo.
 */
@QuarkusTest
class EgressStreamingTest {

  static final String SECRET = "suite-upstream-secret-value";

  static final String EDGE = "dev-qits-edge";

  /** The gap between two chunks of a streamed answer: the first must arrive well before it ends. */
  static final long STREAM_GAP_MILLIS = 1_500;

  static Vertx upstreamVertx;

  static HttpServer upstream;

  static final BlockingQueue<MultiMap> REQUESTS = new LinkedBlockingQueue<>();

  static final BlockingQueue<MultiMap> HANDSHAKES = new LinkedBlockingQueue<>();

  static volatile CountDownLatch slowArrived = new CountDownLatch(1);

  @Inject EgressProxy proxy;

  @Inject GrantTableStore store;

  @Inject GrantIndex index;

  @Inject ObjectMapper json;

  final HttpClient http = HttpClient.newHttpClient();

  final List<String> audit = new CopyOnWriteArrayList<>();

  final Handler capture =
      new Handler() {
        @Override
        public void publish(LogRecord record) {
          audit.add(record.getMessage());
        }

        @Override
        public void flush() {}

        @Override
        public void close() {}
      };

  @BeforeAll
  static void startTheUpstream() throws Exception {
    upstreamVertx = Vertx.vertx();
    upstream =
        upstreamVertx
            .createHttpServer()
            .webSocketHandler(
                socket -> {
                  MultiMap headers = MultiMap.caseInsensitiveMultiMap();
                  headers.addAll(socket.headers());
                  HANDSHAKES.add(headers);
                  socket.textMessageHandler(socket::writeTextMessage);
                })
            .requestHandler(
                request -> {
                  MultiMap headers = MultiMap.caseInsensitiveMultiMap();
                  headers.addAll(request.headers());
                  REQUESTS.add(headers);
                  HttpServerResponse response = request.response();
                  switch (request.path()) {
                    case "/base/split" -> {
                      response.setChunked(true).write("before " + SECRET.substring(0, 11));
                      upstreamVertx.setTimer(
                          100, t -> response.end(SECRET.substring(11) + " after"));
                    }
                    case "/base/fixed" ->
                        response.putHeader("Content-Type", "text/plain").end("your key is " + SECRET);
                    case "/base/redirect" ->
                        response
                            .setStatusCode(302)
                            .putHeader(
                                "Location",
                                "https://example.test/cb?key="
                                    + URLEncoder.encode(SECRET, StandardCharsets.UTF_8))
                            .putHeader(
                                "X-Echo",
                                "Basic "
                                    + Base64.getEncoder()
                                        .encodeToString(SECRET.getBytes(StandardCharsets.UTF_8)))
                            .end();
                    case "/base/events" -> {
                      response
                          .setChunked(true)
                          .putHeader("Content-Type", "text/event-stream")
                          .write("data: one\n\n");
                      upstreamVertx.setTimer(STREAM_GAP_MILLIS, t -> response.end("data: two\n\n"));
                    }
                    case "/base/stream" -> {
                      response.setChunked(true).write("chunk-1\n");
                      upstreamVertx.setTimer(STREAM_GAP_MILLIS, t -> response.end("chunk-2\n"));
                    }
                    case "/base/slow" -> {
                      slowArrived.countDown();
                      upstreamVertx.setTimer(STREAM_GAP_MILLIS, t -> response.end("slow done"));
                    }
                    case "/base/gzip" ->
                        response.putHeader("Content-Encoding", "gzip").end("not really gzip " + SECRET);
                    default -> response.setStatusCode(404).end();
                  }
                })
            .listen(0, "127.0.0.1")
            .toCompletionStage()
            .toCompletableFuture()
            .get(10, TimeUnit.SECONDS);
  }

  @AfterAll
  static void stopTheUpstream() throws Exception {
    upstreamVertx.close().toCompletionStage().toCompletableFuture().get(10, TimeUnit.SECONDS);
  }

  @BeforeEach
  void grant() throws Exception {
    REQUESTS.clear();
    HANDSHAKES.clear();
    Logger.getLogger(AuditLine.LOGGER).addHandler(capture);
    String target = "http://127.0.0.1:" + upstream.actualPort() + "/base";
    GrantTableWire.GrantTable table =
        new GrantTableWire.GrantTable(
            System.currentTimeMillis(),
            List.of(
                new GrantTableWire.Route(
                    "qits-edge",
                    "dev",
                    "2026.1201.101010",
                    "suite",
                    target,
                    "SUITE_UPSTREAM",
                    "header:X-Api-Key",
                    List.of("GET", "POST"))),
            List.of());
    store.clear();
    store.store(table.version(), json.writeValueAsString(table), "application:qits-deployments");
    index.refresh();
  }

  @AfterEach
  void stopListening() {
    Logger.getLogger(AuditLine.LOGGER).removeHandler(capture);
    proxy.reopen();
  }

  private static String token() {
    return MockIdp.ensureStarted()
        .token()
        .subject(EDGE)
        .audience("qits-platform")
        .groups("clients/" + EDGE, "qits:system")
        .mint();
  }

  private HttpResponse<String> get(String path, String... headers) throws Exception {
    HttpRequest.Builder request =
        HttpRequest.newBuilder(URI.create("http://127.0.0.1:" + proxy.port() + path))
            .header("Authorization", "Bearer " + token());
    for (int i = 0; i < headers.length; i += 2) {
      request.header(headers[i], headers[i + 1]);
    }
    return http.send(request.build(), HttpResponse.BodyHandlers.ofString());
  }

  private String auditLine() throws InterruptedException {
    long deadline = System.currentTimeMillis() + 5_000;
    while (audit.isEmpty() && System.currentTimeMillis() < deadline) {
      Thread.sleep(20);
    }
    assertFalse(audit.isEmpty(), "an audit line was written");
    return audit.remove(0);
  }

  // --- scrubbing ---------------------------------------------------------------------------------

  @Test
  void aSecretSplitAcrossTwoChunksIsRedacted() throws Exception {
    HttpResponse<String> answer = get("/suite/split");
    assertEquals(200, answer.statusCode());
    assertEquals("before [redacted] after", answer.body());
    MultiMap seen = REQUESTS.poll(5, TimeUnit.SECONDS);
    assertNotNull(seen);
    assertEquals(SECRET, seen.get("X-Api-Key"), "the secret was injected");
    assertEquals("identity", seen.get("Accept-Encoding"), "the answer must be readable");
  }

  @Test
  void aFixedLengthAnswerLosesItsLengthAndItsSecret() throws Exception {
    HttpResponse<String> answer = get("/suite/fixed", "Accept-Encoding", "gzip, br");
    assertEquals(200, answer.statusCode());
    assertEquals("your key is [redacted]", answer.body());
    assertTrue(answer.headers().firstValue("Content-Length").isEmpty(), answer.headers().toString());
    assertEquals("identity", REQUESTS.poll(5, TimeUnit.SECONDS).get("Accept-Encoding"));
  }

  @Test
  void aLocationHeaderIsRedacted() throws Exception {
    HttpResponse<String> answer = get("/suite/redirect");
    assertEquals(302, answer.statusCode());
    assertEquals(
        "https://example.test/cb?key=[redacted]",
        answer.headers().firstValue("Location").orElse(null));
    assertEquals("Basic [redacted]", answer.headers().firstValue("X-Echo").orElse(null));
  }

  @Test
  void anEncodedAnswerIsRefusedRatherThanPassedUnread() throws Exception {
    HttpResponse<String> answer = get("/suite/gzip");
    assertEquals(502, answer.statusCode());
    assertFalse(answer.body().contains(SECRET));
    assertTrue(answer.body().contains("content encoding"), answer.body());
    String line = auditLine();
    assertTrue(line.contains("decision=ALLOW"), line);
    assertTrue(line.contains("status=502"), line);
    assertTrue(line.endsWith(" reason=upstream-encoded"), line);
  }

  // --- streams -----------------------------------------------------------------------------------

  /** One streamed GET: the whole body and when its first bytes arrived. */
  private record Streamed(String body, long firstChunkMillis) {}

  private Streamed stream(String path, String accept) throws Exception {
    HttpRequest request =
        HttpRequest.newBuilder(URI.create("http://127.0.0.1:" + proxy.port() + path))
            .header("Authorization", "Bearer " + token())
            .header("Accept", accept)
            .build();
    long started = System.nanoTime();
    HttpResponse<InputStream> answer = http.send(request, HttpResponse.BodyHandlers.ofInputStream());
    assertEquals(200, answer.statusCode());
    try (InputStream in = answer.body()) {
      int first = in.read();
      long firstMillis = (System.nanoTime() - started) / 1_000_000;
      byte[] rest = in.readAllBytes();
      return new Streamed(
          (char) first + new String(rest, StandardCharsets.UTF_8), firstMillis);
    }
  }

  @Test
  void aChunkedResponseIsNotBuffered() throws Exception {
    // Ported from qits-edge's EdgeRoutingTest: the FIRST chunk's arrival time is the assertion — a
    // buffering proxy would deliver both at the end, and the body alone would pass either way.
    Streamed streamed = stream("/suite/stream", "*/*");
    assertEquals("chunk-1\nchunk-2\n", streamed.body());
    assertTrue(
        streamed.firstChunkMillis() < STREAM_GAP_MILLIS,
        "the first chunk arrived after " + streamed.firstChunkMillis() + "ms — buffered");
  }

  @Test
  void anSseEventReachesTheClientBeforeTheUpstreamEnds() throws Exception {
    Streamed streamed = stream("/suite/events", "text/event-stream");
    assertEquals("data: one\n\ndata: two\n\n", streamed.body());
    assertTrue(
        streamed.firstChunkMillis() < STREAM_GAP_MILLIS,
        "the first event arrived after " + streamed.firstChunkMillis() + "ms — buffered");
    assertTrue(
        proxy.pools().get(1).open().keySet().stream()
            .anyMatch(origin -> origin.port() == upstream.actualPort()),
        "the event stream went through the stream pool: " + proxy.pools().get(1).open());
  }

  @Test
  void theStreamRuleIsGetOrHeadAskingForEvents() {
    assertTrue(EgressProxy.streams(HttpMethod.GET, List.of("text/event-stream")));
    assertTrue(EgressProxy.streams(HttpMethod.HEAD, List.of("application/json, Text/Event-Stream")));
    assertFalse(EgressProxy.streams(HttpMethod.POST, List.of("application/json, text/event-stream")));
    assertFalse(EgressProxy.streams(HttpMethod.GET, List.of("application/json")));
  }

  // --- websockets --------------------------------------------------------------------------------

  @Test
  void aWebSocketEchoesThroughWithTheSecretInjectedOnTheHandshake() throws Exception {
    String token = token();
    WebSocketConnectOptions options =
        new WebSocketConnectOptions()
            .setHost("127.0.0.1")
            .setPort(proxy.port())
            .setURI("/suite/echo?x=1")
            .addHeader("Authorization", "Bearer " + token)
            .addHeader("Cookie", "session=caller-cookie")
            .addHeader("X-Qits-Project", "qits");
    io.vertx.core.http.HttpClient client = upstreamVertx.createHttpClient();
    WebSocket socket =
        client.webSocket(options).toCompletionStage().toCompletableFuture().get(10, TimeUnit.SECONDS);
    BlockingQueue<String> echoed = new LinkedBlockingQueue<>();
    socket.textMessageHandler(echoed::add);
    socket.writeTextMessage("hello through the gateway");
    assertEquals("hello through the gateway", echoed.poll(10, TimeUnit.SECONDS));

    MultiMap handshake = HANDSHAKES.poll(5, TimeUnit.SECONDS);
    assertNotNull(handshake, "the upstream saw the handshake");
    assertEquals(SECRET, handshake.get("X-Api-Key"), "the secret is injected on the handshake");
    assertNull(handshake.get("Authorization"), "the caller's bearer stays behind");
    assertNull(handshake.get("Cookie"), "the caller's cookie stays behind");
    assertNull(handshake.get("X-Qits-Project"));
    assertEquals("websocket", handshake.get("Upgrade").toLowerCase(java.util.Locale.ROOT));
    assertEquals(1, proxy.inFlight(), "the open socket is a call in flight");

    socket.close().toCompletionStage().toCompletableFuture().get(10, TimeUnit.SECONDS);
    String line = auditLine();
    assertTrue(
        line.startsWith(
            "egress decision=ALLOW principal=application:qits-edge route=suite method=GET"
                + " target=127.0.0.1 path=/base/echo status=101"),
        line);
    assertTrue(line.endsWith(" reason=websocket"), line);
    assertFalse(line.contains(token));
    long deadline = System.currentTimeMillis() + 5_000;
    while (proxy.inFlight() > 0 && System.currentTimeMillis() < deadline) {
      Thread.sleep(20);
    }
    assertEquals(0, proxy.inFlight(), "a closed socket is no call in flight");
    client.close();
  }

  // --- the drain ---------------------------------------------------------------------------------

  @Test
  void aRequestInFlightAtShutdownCompletes() throws Exception {
    slowArrived = new CountDownLatch(1);
    HttpRequest slow =
        HttpRequest.newBuilder(URI.create("http://127.0.0.1:" + proxy.port() + "/suite/slow"))
            .header("Authorization", "Bearer " + token())
            .build();
    CompletableFuture<HttpResponse<String>> answer =
        http.sendAsync(slow, HttpResponse.BodyHandlers.ofString());
    assertTrue(slowArrived.await(10, TimeUnit.SECONDS), "the call reached the upstream");

    long started = System.nanoTime();
    CompletableFuture<Boolean> drained =
        CompletableFuture.supplyAsync(() -> proxy.drain(Duration.ofSeconds(30)));
    Thread.sleep(200);
    assertFalse(drained.isDone(), "the drain waits for the call in flight");
    // A NEW connection is refused while draining.
    HttpClient newcomer = HttpClient.newHttpClient();
    assertThrows(
        IOException.class,
        () ->
            newcomer.send(
                HttpRequest.newBuilder(URI.create("http://127.0.0.1:" + proxy.port() + "/suite/fixed"))
                    .header("Authorization", "Bearer " + token())
                    .build(),
                HttpResponse.BodyHandlers.ofString()));

    assertTrue(drained.get(30, TimeUnit.SECONDS), "everything in flight ended");
    long tookMs = (System.nanoTime() - started) / 1_000_000;
    HttpResponse<String> done = answer.get(5, TimeUnit.SECONDS);
    assertEquals(200, done.statusCode());
    assertEquals("slow done", done.body());
    assertTrue(tookMs >= 500, "the drain waited for the answer: " + tookMs + "ms");
    assertEquals(0, proxy.inFlight());
  }
}
