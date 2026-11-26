package eu.wohlben.qits.egress.proxy;

import static eu.wohlben.qits.egress.proxy.ProxyWire.agentToken;
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
import eu.wohlben.qits.servicemock.idp.MockIdp;
import io.quarkus.test.junit.QuarkusTest;
import io.vertx.core.MultiMap;
import io.vertx.core.Vertx;
import io.vertx.core.http.HttpServer;
import io.vertx.core.json.JsonObject;
import io.vertx.core.net.SocketAddress;
import jakarta.inject.Inject;
import java.io.InputStream;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.concurrent.BlockingQueue;
import java.util.concurrent.LinkedBlockingQueue;
import java.util.concurrent.TimeUnit;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

/**
 * <b>A project's routes</b> (qits-2525, qits-2660) through the real proxy listener: the table
 * grants {@code project:qits} a {@code cookie:sid} route, and an {@code agent:} of project {@code
 * qits} holds it as its project does — the cookie injected, the caller's own {@code Cookie} and
 * {@code Authorization} gone, the upstream's {@code Set-Cookie} dropped. An agent of another project
 * holds none of it: the route's origin is no grant to it, and an outside host reaches it only
 * through the passthrough, which injects nothing and passes {@code Set-Cookie} on.
 */
@QuarkusTest
class ProjectGrantsTest {

  record Received(String uri, MultiMap headers) {}

  static Vertx upstreamVertx;

  static HttpServer upstream;

  static final BlockingQueue<Received> RECEIVED = new LinkedBlockingQueue<>();

  @Inject EgressProxy proxy;

  @Inject GrantTableStore store;

  @Inject GrantIndex index;

  @Inject ObjectMapper json;

  ProxyWire.Audit audit;

  @BeforeAll
  static void startTheUpstream() throws Exception {
    upstreamVertx = Vertx.vertx();
    upstream =
        upstreamVertx
            .createHttpServer()
            .requestHandler(
                request -> {
                  MultiMap headers = MultiMap.caseInsensitiveMultiMap();
                  headers.addAll(request.headers());
                  RECEIVED.add(new Received(request.uri(), headers));
                  request
                      .response()
                      .putHeader("Content-Type", "text/plain")
                      .putHeader("Set-Cookie", "session=fresh-from-the-login-page; Path=/")
                      .putHeader("X-Upstream", "kept")
                      .end("upstream answered");
                })
            .listen(0, "127.0.0.1")
            .toCompletionStage()
            .toCompletableFuture()
            .get(10, TimeUnit.SECONDS);
    PassthroughTest.names();
  }

  @AfterAll
  static void stopTheUpstream() throws Exception {
    upstreamVertx.close().toCompletionStage().toCompletableFuture().get(10, TimeUnit.SECONDS);
  }

  @BeforeEach
  void grant() throws Exception {
    RECEIVED.clear();
    SuitePassthroughNetwork.DIALS.put(
        PassthroughTest.PUBLIC_ADDRESS + ":80",
        SocketAddress.inetSocketAddress(upstream.actualPort(), "127.0.0.1"));
    audit = new ProxyWire.Audit();
    GrantTableWire.GrantTable table =
        new GrantTableWire.GrantTable(
            System.currentTimeMillis(),
            List.of(
                new GrantTableWire.Route(
                    "project:qits",
                    null,
                    null,
                    "0f1e2d3c4b5a",
                    "portal",
                    origin() + "/portal",
                    "PROJECT_QITS_SESSION",
                    "cookie:sid",
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

  private static String origin() {
    return "http://127.0.0.1:" + upstream.actualPort();
  }

  /** An agent of another project, {@code other}. */
  private static String otherProjectsAgent() {
    return MockIdp.ensureStarted()
        .token()
        .subject("tok-agent-other-developer")
        .audience("qits-platform")
        .groups("qits:agent")
        .claim("agent", "stranger")
        .claim("project", "other")
        .mint();
  }

  private record Answer(ProxyWire.Head head, String body) {}

  private Answer raw(String requestHead) throws Exception {
    try (Socket socket = new Socket("127.0.0.1", proxy.port())) {
      socket.setSoTimeout(10_000);
      socket.getOutputStream().write(requestHead.getBytes(StandardCharsets.ISO_8859_1));
      socket.getOutputStream().flush();
      InputStream in = socket.getInputStream();
      ProxyWire.Head head = ProxyWire.head(in);
      return new Answer(head, ProxyWire.body(in, head));
    }
  }

  /** An absolute-form GET carrying the caller's own credentials and cookie. */
  private static String absolute(String url, String host, String token) {
    return "GET " + url + " HTTP/1.1\r\nHost: " + host + "\r\n"
        + "Proxy-Authorization: " + basic(token) + "\r\n"
        + "Authorization: Bearer the-callers-own\r\n"
        + "Cookie: mine=the-callers-own\r\n"
        + "Connection: close\r\n\r\n";
  }

  /** The gateway form: {@code /<route>/<rest>}, the caller's bearer in {@code Authorization}. */
  private static String gateway(String path, String token) {
    return "GET " + path + " HTTP/1.1\r\nHost: egress\r\nAuthorization: Bearer " + token + "\r\n"
        + "Cookie: mine=the-callers-own\r\nConnection: close\r\n\r\n";
  }

  @Test
  void anAgentOfTheProjectHoldsItsRouteAndTheCookieIsInjected() throws Exception {
    Answer answer =
        raw(absolute(origin() + "/portal/v1/me?x=1", "127.0.0.1:" + upstream.actualPort(), agentToken()));
    assertEquals(200, answer.head().status(), answer.body());
    assertEquals("upstream answered", answer.body());
    assertNull(answer.head().headers().get("Set-Cookie"), "a secret route hands out no session");
    assertEquals("kept", answer.head().headers().get("X-Upstream"));

    Received received = RECEIVED.poll(5, TimeUnit.SECONDS);
    assertNotNull(received);
    assertEquals("/portal/v1/me?x=1", received.uri());
    assertEquals(List.of("sid=project-session-secret-value"), received.headers().getAll("Cookie"));
    assertNull(received.headers().get("Authorization"), "the caller's credentials never leave");
    assertNull(received.headers().get("Proxy-Authorization"));

    String line = audit.await(l -> l.contains(" method=GET "));
    assertTrue(
        line.startsWith("egress decision=ALLOW principal=agent:developer route=portal method=GET"),
        line);
    assertFalse(line.contains("passthrough=true"), line);
    assertFalse(line.contains("project-session-secret-value"), line);
  }

  @Test
  void theProjectItselfHoldsItAtTheGateway() throws Exception {
    Answer answer = raw(gateway("/portal/v1/me", projectToken()));
    assertEquals(200, answer.head().status(), answer.body());
    assertNull(answer.head().headers().get("Set-Cookie"));
    Received received = RECEIVED.poll(5, TimeUnit.SECONDS);
    assertNotNull(received);
    assertEquals("/portal/v1/me", received.uri());
    assertEquals(List.of("sid=project-session-secret-value"), received.headers().getAll("Cookie"));
    String line = audit.await(l -> l.contains(" method=GET "));
    assertTrue(
        line.startsWith("egress decision=ALLOW principal=project:qits route=portal method=GET"),
        line);
  }

  @Test
  void anAgentOfAnotherProjectHoldsNoneOfIt() throws Exception {
    String token = otherProjectsAgent();

    // At the gateway: no route of that name for it.
    Answer answer = raw(gateway("/portal/v1/me", token));
    assertEquals(403, answer.head().status(), answer.body());
    assertEquals("no grant", new JsonObject(answer.body()).getString("error"));
    assertTrue(audit.await(l -> true).endsWith(" reason=no-grant"));

    // By origin: the route is no grant to it, so the passthrough judges it (and its port is none).
    answer =
        raw(absolute(origin() + "/portal/v1/me", "127.0.0.1:" + upstream.actualPort(), token));
    assertEquals(403, answer.head().status(), answer.body());
    assertEquals("passthrough refused", new JsonObject(answer.body()).getString("error"));
    assertTrue(audit.await(l -> true).endsWith(" reason=passthrough-port"));
    assertTrue(RECEIVED.isEmpty(), "nothing reached the route's upstream");
  }

  @Test
  void thePassthroughInjectsNothingAndKeepsSetCookie() throws Exception {
    String host = PassthroughTest.PUBLIC;
    Answer answer = raw(absolute("http://" + host + "/login", host, otherProjectsAgent()));
    assertEquals(200, answer.head().status(), answer.body());
    assertEquals(
        "session=fresh-from-the-login-page; Path=/",
        answer.head().headers().get("Set-Cookie"),
        "the caller's own session: passed on");
    Received received = RECEIVED.poll(5, TimeUnit.SECONDS);
    assertNotNull(received);
    assertEquals(List.of("mine=the-callers-own"), received.headers().getAll("Cookie"));
    assertEquals("Bearer the-callers-own", received.headers().get("Authorization"));
    String line = audit.await(l -> l.contains(" method=GET "));
    assertTrue(
        line.startsWith("egress decision=ALLOW principal=agent:stranger route=- method=GET"), line);
    assertTrue(line.endsWith(" passthrough=true"), line);
  }
}
