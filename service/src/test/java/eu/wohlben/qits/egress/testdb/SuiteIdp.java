package eu.wohlben.qits.egress.testdb;

import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpServer;
import eu.wohlben.qits.servicemock.idp.MockIdp;
import java.io.IOException;
import java.io.UncheckedIOException;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;

/**
 * <b>The idp the proxy listener sees in the suites</b>: the discovery document and the token
 * introspection, served here, with {@link MockIdp}'s issuer and JWKS — so every token the suites
 * mint with {@code MockIdp.token()} validates, and the introspection answers whatever a test sets.
 *
 * <p><b>Why not MockIdp's own stubs.</b> A {@code @QuarkusTest} runs in Quarkus' class loader while
 * the config source that points the application at its idp is loaded in another, and MockIdp
 * accepts stubs only on the instance that started it. Everything here crosses loaders through
 * system properties instead: the port, the answer a test sets ({@link #answer}) and what was asked
 * ({@link #introspections}, {@link #lastAuthorization}).
 */
public final class SuiteIdp {

  static final String PORT = "qits.test.suite-idp.port";
  static final String STATUS = "qits.test.suite-idp.introspect-status";
  static final String BODY = "qits.test.suite-idp.introspect-body";
  static final String COUNT = "qits.test.suite-idp.introspections";
  static final String AUTHORIZATION = "qits.test.suite-idp.last-authorization";

  private SuiteIdp() {}

  /** The base url, ending in {@code /idp}; started once per JVM, whichever loader asks first. */
  public static synchronized String ensureStarted() {
    String parked = System.getProperty(PORT);
    if (parked == null) {
      MockIdp idp = MockIdp.ensureStarted();
      String discovery =
          "{\"issuer\":\""
              + idp.issuer()
              + "\",\"jwks_uri\":\""
              + idp.baseUrl()
              + "/jwks\",\"token_endpoint\":\""
              + idp.baseUrl()
              + "/token\"}";
      try {
        HttpServer server = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
        server.createContext(
            "/idp/.well-known/openid-configuration", exchange -> answer(exchange, 200, discovery));
        server.createContext(
            "/idp/api/tokens/introspect",
            exchange -> {
              exchange.getRequestBody().readAllBytes();
              System.setProperty(
                  COUNT, String.valueOf(Integer.getInteger(COUNT, 0) + 1));
              String authorization = exchange.getRequestHeaders().getFirst("Authorization");
              System.setProperty(AUTHORIZATION, authorization == null ? "" : authorization);
              answer(
                  exchange,
                  Integer.parseInt(System.getProperty(STATUS, "404")),
                  System.getProperty(BODY, "{\"error\":\"not_found\"}"));
            });
        server.start();
        parked = String.valueOf(server.getAddress().getPort());
        System.setProperty(PORT, parked);
      } catch (IOException e) {
        throw new UncheckedIOException(e);
      }
    }
    return "http://127.0.0.1:" + parked + "/idp";
  }

  /** What the introspection answers from now on. */
  public static void answer(int status, String body) {
    System.setProperty(STATUS, String.valueOf(status));
    System.setProperty(BODY, body);
  }

  /** How many introspections were asked in this JVM. */
  public static int introspections() {
    return Integer.getInteger(COUNT, 0);
  }

  /** The {@code Authorization} the last introspection carried. */
  public static String lastAuthorization() {
    return System.getProperty(AUTHORIZATION);
  }

  private static void answer(HttpExchange exchange, int status, String body) throws IOException {
    byte[] bytes = body.getBytes(StandardCharsets.UTF_8);
    exchange.getResponseHeaders().set("Content-Type", "application/json");
    exchange.sendResponseHeaders(status, bytes.length);
    try (var out = exchange.getResponseBody()) {
      out.write(bytes);
    }
  }
}
