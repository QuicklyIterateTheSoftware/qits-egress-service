package eu.wohlben.qits.egress.proxy;

import static eu.wohlben.qits.egress.proxy.ProxyWire.applicationToken;
import static eu.wohlben.qits.egress.proxy.ProxyWire.basic;
import static eu.wohlben.qits.egress.proxy.ProxyWire.projectToken;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.fasterxml.jackson.databind.ObjectMapper;
import eu.wohlben.qits.egress.api.GrantTableWire;
import eu.wohlben.qits.egress.grants.GrantIndex;
import eu.wohlben.qits.egress.store.GrantTableStore;
import io.quarkus.test.common.http.TestHTTPResource;
import io.quarkus.test.junit.QuarkusTest;
import io.vertx.core.MultiMap;
import io.vertx.core.Vertx;
import io.vertx.core.http.HttpServer;
import io.vertx.core.json.JsonObject;
import io.vertx.core.net.NetServer;
import io.vertx.core.net.SocketAddress;
import jakarta.inject.Inject;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.net.Socket;
import java.net.URI;
import java.net.URL;
import java.net.http.HttpClient;
import java.net.http.WebSocket;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.concurrent.BlockingQueue;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.CompletionStage;
import java.util.concurrent.LinkedBlockingQueue;
import java.util.concurrent.TimeUnit;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

/**
 * <b>{@code GET /egress/api/forward}</b> (qits-2654) on the Quarkus HTTP server: the upgrade's
 * bearer, the splice to the proxy listener, and the forward's caller standing in for a missing
 * {@code Proxy-Authorization} — but never for one that is there. The client is the JDK's own
 * WebSocket, as {@code qits egress forward} uses; the made-up names are {@link PassthroughTest}'s.
 */
@QuarkusTest
class ForwardDoorTest {

  static final String SECRET = "suite-upstream-secret-value";

  record Received(String uri, MultiMap headers) {}

  static Vertx upstreamVertx;

  static HttpServer upstream;

  static NetServer echo;

  static final BlockingQueue<Received> RECEIVED = new LinkedBlockingQueue<>();

  @TestHTTPResource("/egress/api/forward")
  URL door;

  @Inject EgressProxy proxy;

  @Inject GrantTableStore store;

  @Inject GrantIndex index;

  @Inject ObjectMapper json;

  ProxyWire.Audit audit;

  @BeforeAll
  static void startTheUpstreams() throws Exception {
    upstreamVertx = Vertx.vertx();
    upstream =
        upstreamVertx
            .createHttpServer()
            .requestHandler(
                request -> {
                  MultiMap headers = MultiMap.caseInsensitiveMultiMap();
                  headers.addAll(request.headers());
                  RECEIVED.add(new Received(request.uri(), headers));
                  request.response().putHeader("Content-Type", "text/plain").end("upstream answered");
                })
            .listen(0, "127.0.0.1")
            .toCompletionStage()
            .toCompletableFuture()
            .get(10, TimeUnit.SECONDS);
    echo =
        upstreamVertx
            .createNetServer()
            .connectHandler(socket -> socket.handler(socket::write))
            .listen(0, "127.0.0.1")
            .toCompletionStage()
            .toCompletableFuture()
            .get(10, TimeUnit.SECONDS);
    PassthroughTest.names();
  }

  @AfterAll
  static void stopTheUpstreams() throws Exception {
    upstreamVertx.close().toCompletionStage().toCompletableFuture().get(10, TimeUnit.SECONDS);
  }

  @BeforeEach
  void grant() throws Exception {
    RECEIVED.clear();
    SuitePassthroughNetwork.DIALS.put(
        PassthroughTest.PUBLIC_ADDRESS + ":443",
        SocketAddress.inetSocketAddress(echo.actualPort(), "127.0.0.1"));
    audit = new ProxyWire.Audit();
    GrantTableWire.GrantTable table =
        new GrantTableWire.GrantTable(
            System.currentTimeMillis(),
            List.of(
                new GrantTableWire.Route(
                    "qits-edge",
                    "dev",
                    "2026.1201.101010",
                    "suite",
                    "http://127.0.0.1:" + upstream.actualPort() + "/base",
                    "SUITE_UPSTREAM",
                    "header:X-Api-Key",
                    List.of("GET"))),
            List.of());
    store.clear();
    store.store(table.version(), json.writeValueAsString(table), "application:qits-deployments");
    index.refresh();
  }

  @AfterEach
  void stopListening() {
    audit.close();
  }

  // --- the upgrade -------------------------------------------------------------------------------

  private ProxyWire.Head upgrade(String authorization) throws IOException {
    try (Socket socket = new Socket(door.getHost(), door.getPort())) {
      socket.setSoTimeout(10_000);
      String head =
          "GET " + ForwardDoor.PATH + " HTTP/1.1\r\nHost: " + door.getHost() + "\r\n"
              + "Connection: Upgrade\r\nUpgrade: websocket\r\nSec-WebSocket-Version: 13\r\n"
              + "Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n"
              + (authorization == null ? "" : "Authorization: " + authorization + "\r\n")
              + "\r\n";
      socket.getOutputStream().write(head.getBytes(StandardCharsets.ISO_8859_1));
      socket.getOutputStream().flush();
      return ProxyWire.head(socket.getInputStream());
    }
  }

  @Test
  void anUpgradeWithoutABearerIs401() throws Exception {
    ProxyWire.Head head = upgrade(null);
    assertEquals(401, head.status());
    assertEquals("Bearer realm=\"qits-egress\"", head.headers().get("WWW-Authenticate"));
    String line = audit.await(l -> l.contains(" path=/egress/api/forward "));
    assertTrue(line.startsWith("egress decision=DENY principal=- "), line);
    assertTrue(line.endsWith(" reason=no-credentials via=forward"), line);

    assertEquals(401, upgrade("Bearer not-a-jwt").status());
    assertTrue(audit.await(l -> true).contains(" reason=bad-credentials "));
    assertEquals(0, proxy.forwards().open());
  }

  @Test
  void aBearerOpensTheUpgrade() throws Exception {
    ProxyWire.Head head = upgrade("Bearer " + projectToken());
    assertEquals(101, head.status());
    assertEquals("s3pPLMBiTxaQ9kYGzzhZRbK+xOo=", head.headers().get("Sec-WebSocket-Accept"));
    // The socket closed with the try block: the forward is over and its port released.
    String line = audit.await(l -> l.contains(" path=/egress/api/forward "));
    assertTrue(
        line.startsWith("egress decision=ALLOW principal=project:qits route=- method=GET"), line);
    assertTrue(line.contains(" status=101 "), line);
    assertTrue(line.endsWith(" reason=forward via=forward"), line);
    long deadline = System.currentTimeMillis() + 5_000;
    while (proxy.forwards().open() > 0 && System.currentTimeMillis() < deadline) {
      Thread.sleep(20);
    }
    assertEquals(0, proxy.forwards().open());
  }

  @Test
  void aRequestThatIsNoUpgradeIs400() throws Exception {
    HttpClient client = HttpClient.newHttpClient();
    var answer =
        client.send(
            java.net.http.HttpRequest.newBuilder(door.toURI())
                .header("Authorization", "Bearer " + projectToken())
                .build(),
            java.net.http.HttpResponse.BodyHandlers.ofString());
    assertEquals(400, answer.statusCode());
    assertTrue(audit.await(l -> true).contains(" reason=not-an-upgrade "));
  }

  // --- through the forward -----------------------------------------------------------------------

  /** One forward's websocket, as a byte stream: what arrives is buffered, read as it is needed. */
  static final class Forward implements WebSocket.Listener, AutoCloseable {

    private final BlockingQueue<byte[]> arrived = new LinkedBlockingQueue<>();

    private final CompletableFuture<Integer> closed = new CompletableFuture<>();

    private ByteArrayInputStream current = new ByteArrayInputStream(new byte[0]);

    private WebSocket socket;

    static Forward open(URL door, String bearer) throws Exception {
      Forward forward = new Forward();
      URI uri = URI.create(door.toString().replaceFirst("^http", "ws"));
      forward.socket =
          HttpClient.newBuilder()
              .proxy(HttpClient.Builder.NO_PROXY)
              .build()
              .newWebSocketBuilder()
              .header("Authorization", "Bearer " + bearer)
              .buildAsync(uri, forward)
              .get(10, TimeUnit.SECONDS);
      return forward;
    }

    @Override
    public void onOpen(WebSocket webSocket) {
      webSocket.request(1);
    }

    @Override
    public CompletionStage<?> onBinary(WebSocket webSocket, ByteBuffer data, boolean last) {
      byte[] bytes = new byte[data.remaining()];
      data.get(bytes);
      arrived.add(bytes);
      webSocket.request(1);
      return null;
    }

    @Override
    public CompletionStage<?> onClose(WebSocket webSocket, int statusCode, String reason) {
      closed.complete(statusCode);
      return null;
    }

    @Override
    public void onError(WebSocket webSocket, Throwable error) {
      closed.completeExceptionally(error);
    }

    void send(String text) throws Exception {
      socket
          .sendBinary(ByteBuffer.wrap(text.getBytes(StandardCharsets.ISO_8859_1)), true)
          .get(10, TimeUnit.SECONDS);
    }

    /** The bytes that arrived, as a stream that blocks for more. */
    InputStream in() {
      return new InputStream() {
        @Override
        public int read() throws IOException {
          while (current.available() == 0) {
            byte[] next;
            try {
              next = arrived.poll(10, TimeUnit.SECONDS);
            } catch (InterruptedException e) {
              throw new IOException(e);
            }
            if (next == null) {
              throw new IOException("nothing arrived on the forward");
            }
            current = new ByteArrayInputStream(next);
          }
          return current.read();
        }
      };
    }

    boolean closedWithin(long seconds) {
      try {
        closed.get(seconds, TimeUnit.SECONDS);
        return true;
      } catch (Exception e) {
        return closed.isDone();
      }
    }

    @Override
    public void close() {
      socket.sendClose(WebSocket.NORMAL_CLOSURE, "done");
    }
  }

  private record Answer(ProxyWire.Head head, String body) {}

  private static Answer answer(Forward forward) throws IOException {
    InputStream in = forward.in();
    ProxyWire.Head head = ProxyWire.head(in);
    return new Answer(head, ProxyWire.body(in, head));
  }

  @Test
  void aForwardedConnectIsSplicedToAPublicUpstream() throws Exception {
    String token = projectToken();
    try (Forward forward = Forward.open(door, token)) {
      forward.send(
          "CONNECT " + PassthroughTest.PUBLIC + ":443 HTTP/1.1\r\nHost: " + PassthroughTest.PUBLIC
              + ":443\r\n\r\n");
      InputStream in = forward.in();
      ProxyWire.Head head = ProxyWire.head(in);
      assertEquals(200, head.status());
      forward.send("through two splices\n");
      ByteArrayOutputStream echoed = new ByteArrayOutputStream();
      while (echoed.size() < "through two splices\n".length()) {
        echoed.write(in.read());
      }
      assertEquals("through two splices\n", echoed.toString(StandardCharsets.US_ASCII));
    }
    String line = audit.await(l -> l.contains(" method=CONNECT "));
    assertTrue(
        line.startsWith(
            "egress decision=ALLOW principal=project:qits route=- method=CONNECT target="
                + PassthroughTest.PUBLIC + ":443 path=- status=200"),
        line);
    assertTrue(line.endsWith(" passthrough=true via=forward"), line);
    assertFalse(line.contains(token));
    assertTrue(audit.await(l -> l.contains(" path=/egress/api/forward ")).endsWith(" via=forward"));
  }

  @Test
  void theForwardsCallerStandsInForAMissingProxyAuthorization() throws Exception {
    try (Forward forward = Forward.open(door, applicationToken())) {
      forward.send(
          "GET http://127.0.0.1:" + upstream.actualPort() + "/base/v1 HTTP/1.1\r\nHost: 127.0.0.1\r\n"
              + "Connection: close\r\n\r\n");
      Answer answer = answer(forward);
      assertEquals(200, answer.head().status(), answer.body());
      assertEquals("upstream answered", answer.body());
      // The listener closes a Connection: close exchange, and the forward with it.
      assertTrue(forward.closedWithin(5), "the forward closes with the listener's connection");
    }
    Received received = RECEIVED.poll(5, TimeUnit.SECONDS);
    assertNotNull(received);
    assertEquals(SECRET, received.headers().get("X-Api-Key"));
    String line = audit.await(l -> l.contains(" path=/base/v1 "));
    assertTrue(
        line.startsWith("egress decision=ALLOW principal=application:qits-edge route=suite method=GET"),
        line);
    assertTrue(line.endsWith(" via=forward"), line);
  }

  @Test
  void aProxyAuthorizationOnTheForwardWins() throws Exception {
    try (Forward forward = Forward.open(door, applicationToken())) {
      // The forward is the application's; the request names a project, which holds no route and
      // whose passthrough refuses the port.
      forward.send(
          "GET http://127.0.0.1:" + upstream.actualPort() + "/base/v1 HTTP/1.1\r\nHost: 127.0.0.1\r\n"
              + "Proxy-Authorization: " + basic(projectToken()) + "\r\n\r\n");
      Answer answer = answer(forward);
      assertEquals(403, answer.head().status(), answer.body());
      assertEquals("project:qits", new JsonObject(answer.body()).getString("principal"));
      String line = audit.await(l -> l.contains(" path=/base/v1 "));
      assertTrue(line.startsWith("egress decision=DENY principal=project:qits "), line);
      assertTrue(line.endsWith(" reason=passthrough-port via=forward"), line);

      // A bad one is a 407 on the same forward: it decides, the forward's caller does not.
      forward.send(
          "GET http://127.0.0.1:" + upstream.actualPort() + "/base/v1 HTTP/1.1\r\nHost: 127.0.0.1\r\n"
              + "Proxy-Authorization: " + basic("not-a-jwt") + "\r\n\r\n");
      answer = answer(forward);
      assertEquals(407, answer.head().status(), answer.body());
      assertTrue(audit.await(l -> l.contains(" path=/base/v1 ")).endsWith(" reason=bad-credentials via=forward"));
    }
    assertTrue(RECEIVED.isEmpty());
    assertNull(RECEIVED.poll());
  }
}
