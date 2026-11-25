package eu.wohlben.qits.egress.proxy;

import static eu.wohlben.qits.egress.proxy.ProxyWire.agentToken;
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
import io.quarkus.test.junit.QuarkusTest;
import io.vertx.core.MultiMap;
import io.vertx.core.Vertx;
import io.vertx.core.http.HttpServer;
import io.vertx.core.json.JsonObject;
import io.vertx.core.net.NetServer;
import io.vertx.core.net.SocketAddress;
import jakarta.inject.Inject;
import java.io.InputStream;
import java.io.OutputStream;
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
 * <b>The passthrough</b> (qits-2654) through the real proxy listener: a principal with a project
 * reaches an outside host no route covers — {@code CONNECT :443} spliced blind, absolute-form {@code
 * http://} on :80 forwarded with the caller's own credentials — and every refusal reason. The names
 * are made up ({@link SuitePassthroughNetwork}): {@code public.passthrough.test} resolves to {@code
 * 203.0.113.7}, which the check sees and the suite dials on loopback, where the fake upstreams are.
 */
@QuarkusTest
class PassthroughTest {

  static final String PUBLIC = "public.passthrough.test";

  static final String PUBLIC_ADDRESS = "203.0.113.7";

  record Received(String uri, MultiMap headers) {}

  static Vertx upstreamVertx;

  static HttpServer upstream;

  static NetServer echo;

  static final BlockingQueue<Received> RECEIVED = new LinkedBlockingQueue<>();

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
    names();
  }

  /** The made-up names, shared with {@link ForwardDoorTest}. */
  static void names() {
    SuitePassthroughNetwork.NAMES.put(PUBLIC, List.of(PUBLIC_ADDRESS));
    SuitePassthroughNetwork.NAMES.put("loopback.passthrough.test", List.of("127.0.0.1"));
    SuitePassthroughNetwork.NAMES.put("ten.passthrough.test", List.of("10.20.30.40"));
    SuitePassthroughNetwork.NAMES.put("mixed.passthrough.test", List.of("203.0.113.8", "10.0.0.9"));
    SuitePassthroughNetwork.NAMES.put("metadata.passthrough.test", List.of("169.254.169.254"));
  }

  @AfterAll
  static void stopTheUpstreams() throws Exception {
    upstreamVertx.close().toCompletionStage().toCompletableFuture().get(10, TimeUnit.SECONDS);
  }

  @BeforeEach
  void grant() throws Exception {
    RECEIVED.clear();
    SuitePassthroughNetwork.DIALS.put(
        PUBLIC_ADDRESS + ":443", SocketAddress.inetSocketAddress(echo.actualPort(), "127.0.0.1"));
    SuitePassthroughNetwork.DIALS.put(
        PUBLIC_ADDRESS + ":80", SocketAddress.inetSocketAddress(upstream.actualPort(), "127.0.0.1"));
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

  private static String connect(String authority, String token) {
    return "CONNECT " + authority + " HTTP/1.1\r\nHost: " + authority + "\r\nProxy-Authorization: "
        + basic(token) + "\r\n\r\n";
  }

  private static String get(String url, String token) {
    return "GET " + url + " HTTP/1.1\r\nHost: x\r\nProxy-Authorization: " + basic(token)
        + "\r\nConnection: close\r\n\r\n";
  }

  @Test
  void aProjectsConnectIsSplicedBlind() throws Exception {
    String token = projectToken();
    try (Socket socket = new Socket("127.0.0.1", proxy.port())) {
      socket.setSoTimeout(10_000);
      OutputStream out = socket.getOutputStream();
      out.write(connect(PUBLIC + ":443", token).getBytes(StandardCharsets.ISO_8859_1));
      out.flush();
      InputStream in = socket.getInputStream();
      ProxyWire.Head head = ProxyWire.head(in);
      assertEquals(200, head.status());
      // The bytes go as they come: no TLS is ended here, the echo answers them raw.
      byte[] bytes = "not even TLS\n".getBytes(StandardCharsets.US_ASCII);
      out.write(bytes);
      out.flush();
      assertEquals("not even TLS\n", new String(in.readNBytes(bytes.length), StandardCharsets.US_ASCII));
    }
    String line = audit.await(l -> l.contains(" method=CONNECT "));
    assertTrue(
        line.startsWith(
            "egress decision=ALLOW principal=project:qits route=- method=CONNECT target=" + PUBLIC
                + ":443 path=- status=200"),
        line);
    assertTrue(line.endsWith(" reason=- passthrough=true"), line);
    assertFalse(line.contains("tls=intercepted"), line);
    assertFalse(line.contains(token));
  }

  @Test
  void anAgentsHttpGoesOutWithItsOwnCredentials() throws Exception {
    Answer answer =
        raw(
            "GET http://" + PUBLIC + "/p/v1?q=1 HTTP/1.1\r\nHost: " + PUBLIC + "\r\n"
                + "Proxy-Authorization: " + basic(agentToken()) + "\r\n"
                + "Authorization: Bearer the-callers-own\r\n"
                + "Cookie: session=the-callers-own\r\n"
                + "Proxy-Connection: keep-alive\r\n"
                + "Connection: close\r\n\r\n");
    assertEquals(200, answer.head().status(), answer.body());
    assertEquals("upstream answered", answer.body());
    Received received = RECEIVED.poll(5, TimeUnit.SECONDS);
    assertNotNull(received);
    assertEquals("/p/v1?q=1", received.uri());
    assertEquals("Bearer the-callers-own", received.headers().get("Authorization"));
    assertEquals("session=the-callers-own", received.headers().get("Cookie"));
    assertNull(received.headers().get("Proxy-Authorization"));
    assertNull(received.headers().get("Proxy-Connection"));
    assertNull(received.headers().get("X-Api-Key"), "nothing is injected");
    assertTrue(received.headers().get("Host").startsWith(PUBLIC), received.headers().get("Host"));
    String line = audit.await(l -> l.contains(" method=GET "));
    assertTrue(
        line.startsWith(
            "egress decision=ALLOW principal=agent:developer route=- method=GET target=" + PUBLIC
                + " path=/p/v1 status=200"),
        line);
    assertTrue(line.endsWith(" passthrough=true"), line);
  }

  @Test
  void everyRefusalSaysWhy() throws Exception {
    String token = projectToken();
    String[][] cases = {
      {connect(PUBLIC + ":8443", token), "port"},
      {get("http://" + PUBLIC + ":8080/x", token), "port"},
      {connect("qits.wohlben.eu:443", token), "platform-host"},
      {connect("idp.qits.wohlben.eu:443", token), "platform-host"},
      {get("http://registry.qits.wohlben.eu/x", token), "platform-host"},
      {connect("dev-qits-idp:443", token), "single-label"},
      {get("http://dev-qits-projects/x", token), "single-label"},
      {connect("loopback.passthrough.test:443", token), "private-address"},
      {connect("ten.passthrough.test:443", token), "private-address"},
      {get("http://ten.passthrough.test/x", token), "private-address"},
      {connect("mixed.passthrough.test:443", token), "private-address"},
      {connect("metadata.passthrough.test:443", token), "private-address"},
      {connect("10.1.2.3:443", token), "private-address"},
      {connect("127.0.0.1:443", token), "private-address"},
      {connect("[::1]:443", token), "private-address"},
    };
    for (String[] refusal : cases) {
      Answer answer = raw(refusal[0]);
      String what = refusal[0].lines().findFirst().orElseThrow();
      assertEquals(403, answer.head().status(), what + ": " + answer.body());
      JsonObject body = new JsonObject(answer.body());
      assertEquals("passthrough refused", body.getString("error"), what);
      assertEquals(refusal[1], body.getString("reason"), what);
      assertEquals("project:qits", body.getString("principal"), what);
      String line = audit.await(l -> true);
      assertTrue(line.startsWith("egress decision=DENY principal=project:qits route=- "), line);
      assertTrue(line.endsWith(" reason=passthrough-" + refusal[1]), what + ": " + line);
    }
    assertTrue(RECEIVED.isEmpty());
  }

  @Test
  void anApplicationWithoutARouteIsStillForbidden() throws Exception {
    String token = applicationToken();
    Answer answer = raw(connect(PUBLIC + ":443", token));
    assertEquals(403, answer.head().status(), answer.body());
    assertEquals("no grant", new JsonObject(answer.body()).getString("error"));
    String line = audit.await(l -> true);
    assertTrue(line.startsWith("egress decision=DENY principal=application:qits-edge"), line);
    assertTrue(line.endsWith(" reason=no-grant"), line);

    answer = raw(get("http://" + PUBLIC + "/x", token));
    assertEquals(403, answer.head().status(), answer.body());
    assertEquals("no grant", new JsonObject(answer.body()).getString("error"));
    assertTrue(audit.await(l -> true).endsWith(" reason=no-grant"));
    assertTrue(RECEIVED.isEmpty());
  }

  @Test
  void aProjectHoldsNoApplicationsRoute() throws Exception {
    // An application's route is no grant for a project (qits-2660 adds project routes): its
    // origin is judged by the passthrough, and its port is no passthrough port.
    Answer answer =
        raw(get("http://127.0.0.1:" + upstream.actualPort() + "/base/v1", projectToken()));
    assertEquals(403, answer.head().status());
    assertEquals("port", new JsonObject(answer.body()).getString("reason"));
    audit.await(l -> true);
    assertTrue(RECEIVED.isEmpty());
  }
}
