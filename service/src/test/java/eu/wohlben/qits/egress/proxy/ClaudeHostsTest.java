package eu.wohlben.qits.egress.proxy;

import static eu.wohlben.qits.egress.proxy.ProxyWire.agentToken;
import static eu.wohlben.qits.egress.proxy.ProxyWire.applicationToken;
import static eu.wohlben.qits.egress.proxy.ProxyWire.basic;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import eu.wohlben.qits.egress.claude.ClaudeCredentials;
import eu.wohlben.qits.egress.store.ClaudeCredentialStore;
import eu.wohlben.qits.egress.support.SuiteTls;
import io.quarkus.test.junit.QuarkusTest;
import io.vertx.core.MultiMap;
import io.vertx.core.Vertx;
import io.vertx.core.http.HttpServer;
import io.vertx.core.http.HttpServerOptions;
import io.vertx.core.http.HttpServerRequest;
import io.vertx.core.http.HttpServerResponse;
import io.vertx.core.json.JsonObject;
import io.vertx.core.net.HostAndPort;
import io.vertx.core.net.KeyCertOptions;
import jakarta.inject.Inject;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.time.Instant;
import java.util.Base64;
import java.util.List;
import java.util.concurrent.BlockingQueue;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.LinkedBlockingQueue;
import java.util.concurrent.TimeUnit;
import javax.net.ssl.SNIHostName;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLParameters;
import javax.net.ssl.SSLSocket;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

/**
 * <b>The Claude hosts</b> (qits-2664): an agent of a project opens {@code CONNECT
 * api.anthropic.com:443} (or {@code platform.claude.com:443}) with no route for it; the tunnel is
 * intercepted, the placeholder bearer is swapped for the held access token and any other bearer
 * passes unchanged, Claude Code's placeholder refresh is answered here, the held tokens are
 * scrubbed out of the answers — an SSE answer still streamed — a WebSocket handshake takes the same
 * swap, and with nothing held a placeholder request is 503. An application gets none of it.
 *
 * <p>The Claude hosts are dialled on the suite's fake https upstream ({@link SuiteClaudeUpstream}:
 * {@code localhost:<port>}, its certificate for {@code localhost}); the request still names the
 * Claude host in {@code Host}.
 */
@QuarkusTest
class ClaudeHostsTest {

  static final String API = "api.anthropic.com";

  static final String PLATFORM = "platform.claude.com";

  static final String ACCESS = "sk-ant-oat01-held-access-7f3e";

  static final String REFRESH = "sk-ant-ort01-held-refresh-2c9d";

  static final String SCOPES = "user:inference user:profile user:sessions:claude_code";

  record Received(String method, String uri, MultiMap headers, String body) {}

  static Vertx upstreamVertx;

  static HttpServer upstream;

  static final BlockingQueue<Received> RECEIVED = new LinkedBlockingQueue<>();

  /** Completed by the stream test once it has read the first event: the upstream then ends. */
  static volatile CompletableFuture<Void> release = new CompletableFuture<>();

  @Inject EgressProxy proxy;

  @Inject ClaudeCredentialStore store;

  @Inject ClaudeCredentials credentials;

  ProxyWire.Audit audit;

  @BeforeAll
  static void startTheUpstream() throws Exception {
    upstreamVertx = Vertx.vertx();
    upstream =
        upstreamVertx
            .createHttpServer(
                new HttpServerOptions()
                    .setSsl(true)
                    .setKeyCertOptions(
                        KeyCertOptions.wrap(SuiteTls.ca(SuiteTls.UPSTREAM).server("localhost"))))
            .requestHandler(ClaudeHostsTest::answer)
            .listen(0, "127.0.0.1")
            .toCompletionStage()
            .toCompletableFuture()
            .get(10, TimeUnit.SECONDS);
  }

  private static void answer(HttpServerRequest request) {
    MultiMap headers = MultiMap.caseInsensitiveMultiMap().addAll(request.headers());
    if (request.path().equals("/v1/ws")) {
      RECEIVED.add(new Received(request.method().name(), request.uri(), headers, ""));
      request.toWebSocket().onSuccess(socket -> socket.writeTextMessage("hello"));
      return;
    }
    request
        .body()
        .onSuccess(
            body -> {
              RECEIVED.add(
                  new Received(request.method().name(), request.uri(), headers, body.toString()));
              HttpServerResponse response = request.response();
              switch (request.path()) {
                case "/v1/stream" -> {
                  response
                      .setChunked(true)
                      .putHeader("Content-Type", "text/event-stream")
                      .write("data: one\n\n");
                  CompletableFuture<Void> gate = release;
                  long safety = upstreamVertx.setTimer(10_000, t -> gate.complete(null));
                  gate.thenRun(
                      () ->
                          upstreamVertx.runOnContext(
                              v -> {
                                upstreamVertx.cancelTimer(safety);
                                response.end("data: two\n\n");
                              }));
                }
                case "/echo" ->
                    response
                        .putHeader("Content-Type", "text/plain")
                        .putHeader("X-Echo", "Bearer " + ACCESS)
                        .end(
                            "access="
                                + ACCESS
                                + " refresh="
                                + REFRESH
                                + " b64="
                                + Base64.getEncoder()
                                    .encodeToString(ACCESS.getBytes(StandardCharsets.UTF_8)));
                default ->
                    response
                        .putHeader("Content-Type", "text/plain")
                        .putHeader("Set-Cookie", "session=from-anthropic; Path=/")
                        .end("upstream answered");
              }
            });
  }

  @AfterAll
  static void stopTheUpstream() throws Exception {
    SuiteClaudeUpstream.DIALS.clear();
    upstreamVertx.close().toCompletionStage().toCompletableFuture().get(10, TimeUnit.SECONDS);
  }

  @BeforeEach
  void holdALogin() {
    RECEIVED.clear();
    release = new CompletableFuture<>();
    for (String host : List.of(API, PLATFORM, "claude.ai")) {
      SuiteClaudeUpstream.DIALS.put(host, HostAndPort.create("localhost", upstream.actualPort()));
    }
    store.clear();
    store.replace(
        new ClaudeCredentialStore.Login(
            ACCESS,
            REFRESH,
            Instant.now().plus(Duration.ofHours(8)),
            null,
            SCOPES,
            "max",
            "tier",
            "hand-over suite"));
    credentials.reload();
    audit = new ProxyWire.Audit();
  }

  @AfterEach
  void forget() {
    audit.close();
    store.clear();
    credentials.reload();
  }

  // --- the wire ----------------------------------------------------------------------------------

  private Socket connect(String authority, String token) throws IOException {
    Socket socket = new Socket("127.0.0.1", proxy.port());
    socket.setSoTimeout(10_000);
    send(
        socket.getOutputStream(),
        "CONNECT " + authority + " HTTP/1.1\r\nHost: " + authority + "\r\nProxy-Authorization: "
            + basic(token) + "\r\n\r\n");
    return socket;
  }

  /** An intercepted tunnel to {@code host}: our leaf, trusted alone. */
  private SSLSocket tunnel(String host) throws Exception {
    Socket tunnel = connect(host + ":443", agentToken());
    assertEquals(200, ProxyWire.head(tunnel.getInputStream()).status());
    SSLContext context = SuiteTls.ca(SuiteTls.LEAF).clientContext();
    SSLSocket tls = (SSLSocket) context.getSocketFactory().createSocket(tunnel, host, 443, true);
    SSLParameters parameters = tls.getSSLParameters();
    parameters.setServerNames(List.of(new SNIHostName(host)));
    parameters.setEndpointIdentificationAlgorithm("HTTPS");
    parameters.setApplicationProtocols(new String[] {"http/1.1"});
    tls.setSSLParameters(parameters);
    tls.startHandshake();
    return tls;
  }

  private static void send(OutputStream out, String head) throws IOException {
    out.write(head.getBytes(StandardCharsets.ISO_8859_1));
    out.flush();
  }

  private static String get(String path, String host, String authorization) {
    return "GET " + path + " HTTP/1.1\r\nHost: " + host + "\r\n"
        + (authorization == null ? "" : "Authorization: " + authorization + "\r\n")
        + "Cookie: mine=the-callers-own\r\n"
        + "X-Qits-Caller: dev-qits-agents\r\n\r\n";
  }

  private static String post(String path, String host, String type, String body) {
    byte[] bytes = body.getBytes(StandardCharsets.UTF_8);
    return "POST " + path + " HTTP/1.1\r\nHost: " + host + "\r\n"
        + "Content-Type: " + type + "\r\nContent-Length: " + bytes.length + "\r\n\r\n" + body;
  }

  record Answer(ProxyWire.Head head, String body) {}

  private static Answer exchange(SSLSocket tls, String request) throws IOException {
    send(tls.getOutputStream(), request);
    InputStream in = tls.getInputStream();
    ProxyWire.Head head = ProxyWire.head(in);
    return new Answer(head, ProxyWire.body(in, head));
  }

  // --- the tests ---------------------------------------------------------------------------------

  @Test
  void thePlaceholderIsSwappedAndARealBearerPassesUnchanged() throws Exception {
    try (SSLSocket tls = tunnel(API)) {
      Answer swapped = exchange(tls, get("/v1/models", API, "Bearer qits-egress-placeholder"));
      assertEquals(200, swapped.head().status());
      assertEquals("upstream answered", swapped.body());
      assertNull(swapped.head().headers().get("Set-Cookie"), "the held login's session stays here");
      Received received = RECEIVED.poll(5, TimeUnit.SECONDS);
      assertNotNull(received);
      assertEquals("/v1/models", received.uri());
      assertEquals("Bearer " + ACCESS, received.headers().get("Authorization"), "swapped");
      assertEquals(API, received.headers().get("Host"));
      assertEquals("mine=the-callers-own", received.headers().get("Cookie"), "the caller's");
      assertNull(received.headers().get("Proxy-Authorization"));
      assertNull(received.headers().get("X-Qits-Caller"), "the platform's context stays");
      String line = audit.await(l -> l.contains(" method=GET "));
      assertTrue(
          line.startsWith(
              "egress decision=ALLOW principal=agent:developer route=claude method=GET target="
                  + API + " path=/v1/models status=200"),
          line);
      assertTrue(line.endsWith(" tls=intercepted"), line);

      Answer own = exchange(tls, get("/v1/models", API, "Bearer sk-ant-oat01-the-callers-own"));
      assertEquals(200, own.head().status());
      assertEquals(
          "session=from-anthropic; Path=/",
          own.head().headers().get("Set-Cookie"),
          "the caller's own session");
      received = RECEIVED.poll(5, TimeUnit.SECONDS);
      assertNotNull(received);
      assertEquals(
          "Bearer sk-ant-oat01-the-callers-own",
          received.headers().get("Authorization"),
          "any other bearer is forwarded unchanged");
    }
    String connect = audit.await(l -> l.contains(" method=CONNECT "));
    assertTrue(
        connect.startsWith(
            "egress decision=ALLOW principal=agent:developer route=claude method=CONNECT target="
                + API + ":443 path=- status=200"),
        connect);
    assertTrue(connect.contains(" tls=intercepted leafSerial="), connect);
    assertFalse(String.join("\n", audit.lines).contains(ACCESS));
  }

  @Test
  void thePlaceholdersRefreshIsAnsweredHereAndARealOneGoesOn() throws Exception {
    try (SSLSocket tls = tunnel(PLATFORM)) {
      JsonObject expected = ClaudeHosts.placeholderToken(SCOPES);
      Answer json =
          exchange(
              tls,
              post(
                  "/v1/oauth/token",
                  PLATFORM,
                  "application/json",
                  "{\"grant_type\":\"refresh_token\",\"refresh_token\":\"qits-egress-placeholder\","
                      + "\"client_id\":\"9d1c250a-e61b-44d9-88ed-5944d1962f5e\"}"));
      assertEquals(200, json.head().status());
      assertEquals(expected, new JsonObject(json.body()));
      assertEquals("qits-egress-placeholder", expected.getString("access_token"));
      assertEquals(31536000L, expected.getLong("expires_in"));
      assertEquals(SCOPES, expected.getString("scope"));
      assertTrue(
          audit.await(l -> l.contains(" method=POST ")).contains(" route=claude "), "audited");

      Answer form =
          exchange(
              tls,
              post(
                  "/v1/oauth/token",
                  PLATFORM,
                  "application/x-www-form-urlencoded",
                  "grant_type=refresh_token&refresh_token=qits-egress-placeholder"));
      assertEquals(200, form.head().status());
      assertEquals(expected, new JsonObject(form.body()));
      assertNull(RECEIVED.poll(200, TimeUnit.MILLISECONDS), "never forwarded");

      String real =
          "{\"grant_type\":\"refresh_token\",\"refresh_token\":\"sk-ant-ort01-a-containers-own\"}";
      Answer forwarded = exchange(tls, post("/v1/oauth/token", PLATFORM, "application/json", real));
      assertEquals(200, forwarded.head().status());
      assertEquals("upstream answered", forwarded.body());
      Received received = RECEIVED.poll(5, TimeUnit.SECONDS);
      assertNotNull(received, "a real refresh goes on");
      assertEquals("POST", received.method());
      assertEquals(real, received.body(), "with its body intact");
    }
  }

  @Test
  void theHeldTokensAreScrubbedFromAnswers() throws Exception {
    try (SSLSocket tls = tunnel(API)) {
      Answer echoed = exchange(tls, get("/echo", API, "Bearer qits-egress-placeholder"));
      assertEquals(200, echoed.head().status());
      assertFalse(echoed.body().contains(ACCESS), echoed.body());
      assertFalse(echoed.body().contains(REFRESH), echoed.body());
      assertFalse(
          echoed.body().contains(
              Base64.getEncoder().withoutPadding().encodeToString(ACCESS.getBytes(StandardCharsets.UTF_8))),
          echoed.body());
      assertTrue(echoed.body().startsWith("access=[redacted] refresh=[redacted] b64=[redacted]"), echoed.body());
      assertEquals("Bearer [redacted]", echoed.head().headers().get("X-Echo"));
      // A caller with its own bearer is still never handed the held login.
      Answer own = exchange(tls, get("/echo", API, "Bearer sk-ant-oat01-the-callers-own"));
      assertFalse(own.body().contains(ACCESS), own.body());
    }
  }

  @Test
  void anSseAnswerIsStreamedNotBuffered() throws Exception {
    try (SSLSocket tls = tunnel(API)) {
      send(
          tls.getOutputStream(),
          "POST /v1/stream HTTP/1.1\r\nHost: " + API + "\r\nAuthorization: Bearer"
              + " qits-egress-placeholder\r\nAccept: text/event-stream\r\nContent-Type:"
              + " application/json\r\nContent-Length: 2\r\n\r\n{}");
      InputStream in = tls.getInputStream();
      ProxyWire.Head head = ProxyWire.head(in);
      assertEquals(200, head.status());
      // The first event arrives while the upstream is still holding the answer open.
      String size = line(in);
      String first = new String(in.readNBytes(Integer.parseInt(size.trim(), 16)), StandardCharsets.UTF_8);
      assertEquals("data: one\n\n", first);
      assertFalse(release.isDone(), "read before the upstream ended");
      release.complete(null);
      line(in);
      StringBuilder rest = new StringBuilder();
      while (true) {
        int n = Integer.parseInt(line(in).trim(), 16);
        if (n == 0) {
          break;
        }
        rest.append(new String(in.readNBytes(n), StandardCharsets.UTF_8));
        line(in);
      }
      assertEquals("data: two\n\n", rest.toString());
      Received received = RECEIVED.poll(5, TimeUnit.SECONDS);
      assertNotNull(received);
      assertEquals("Bearer " + ACCESS, received.headers().get("Authorization"));
    }
  }

  private static String line(InputStream in) throws IOException {
    StringBuilder line = new StringBuilder();
    int b;
    while ((b = in.read()) != '\n') {
      if (b < 0) {
        throw new IOException("closed mid-line");
      }
      if (b != '\r') {
        line.append((char) b);
      }
    }
    return line.toString();
  }

  @Test
  void aWebSocketHandshakeGetsTheSameSwap() throws Exception {
    try (SSLSocket tls = tunnel(API)) {
      send(
          tls.getOutputStream(),
          "GET /v1/ws HTTP/1.1\r\nHost: " + API + "\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n"
              + "Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\n"
              + "Authorization: Bearer qits-egress-placeholder\r\n\r\n");
      ProxyWire.Head head = ProxyWire.head(tls.getInputStream());
      assertEquals(101, head.status());
      Received received = RECEIVED.poll(5, TimeUnit.SECONDS);
      assertNotNull(received);
      assertEquals("Bearer " + ACCESS, received.headers().get("Authorization"));
    }
  }

  @Test
  void withNothingHeldAPlaceholderRequestIs503() throws Exception {
    store.clear();
    credentials.reload();
    try (SSLSocket tls = tunnel(API)) {
      Answer refused = exchange(tls, get("/v1/models", API, "Bearer qits-egress-placeholder"));
      assertEquals(503, refused.head().status());
      assertEquals(new JsonObject().put("error", "no claude credential held"), new JsonObject(refused.body()));
      assertTrue(
          audit.await(l -> l.contains(" method=GET ")).contains(" reason=no-claude-credential "));
      Answer own = exchange(tls, get("/v1/models", API, "Bearer sk-ant-oat01-the-callers-own"));
      assertEquals(200, own.head().status(), "a container not cut over still works");
    }
    try (SSLSocket tls = tunnel(PLATFORM)) {
      Answer refresh =
          exchange(
              tls,
              post(
                  "/v1/oauth/token",
                  PLATFORM,
                  "application/json",
                  "{\"refresh_token\":\"qits-egress-placeholder\"}"));
      assertEquals(503, refresh.head().status());
    }
    assertEquals(1, RECEIVED.size(), "only the caller's own bearer went upstream");
  }

  @Test
  void anApplicationGetsNoClaudeTunnel() throws Exception {
    try (Socket tunnel = connect(API + ":443", applicationToken())) {
      ProxyWire.Head head = ProxyWire.head(tunnel.getInputStream());
      assertNotEquals(200, head.status());
    }
    assertTrue(RECEIVED.isEmpty());
  }

  @Test
  void theClaudeHostsAreServedOn443Only() {
    var agent = new eu.wohlben.qits.egress.identity.Principal("agent", "developer", "qits");
    assertTrue(proxyHosts().serves(agent, "api.anthropic.com", 443));
    assertTrue(proxyHosts().serves(agent, "CLAUDE.ai", 443));
    assertFalse(proxyHosts().serves(agent, "api.anthropic.com", 8443));
    assertFalse(proxyHosts().serves(agent, "anthropic.com", 443));
    assertFalse(
        proxyHosts()
            .serves(new eu.wohlben.qits.egress.identity.Principal("application", "qits-edge"), API, 443));
    assertTrue(ClaudeHosts.isPlaceholder("bearer qits-egress-placeholder"));
    assertFalse(ClaudeHosts.isPlaceholder("Bearer qits-egress-placeholder-not"));
    assertFalse(ClaudeHosts.isPlaceholder("Basic qits-egress-placeholder"));
  }

  @Inject ClaudeHosts injectedHosts;

  private ClaudeHosts proxyHosts() {
    return injectedHosts;
  }
}
