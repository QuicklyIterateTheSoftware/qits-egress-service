package eu.wohlben.qits.egress.testdb;

import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpServer;
import eu.wohlben.qits.servicemock.idp.MockIdp;
import java.io.IOException;
import java.io.UncheckedIOException;
import java.net.InetSocketAddress;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Base64;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * <b>The idp the proxy listener sees in the suites</b>: the discovery document, the token
 * introspection and the token EXCHANGE, served here, with {@link MockIdp}'s issuer and JWKS — so
 * every token the suites mint with {@code MockIdp.token()} validates, the introspection answers
 * whatever a test sets, and an exchange mints a JWT whose {@code sub} and {@code groups} are the
 * subject's and whose {@code act.sub} is the asking client, as qits-idp does (qits-2613).
 *
 * <p><b>And the suites' platform service</b>: {@code /platform/<label>/…} on the same server is
 * where a platform route goes in the suites ({@link #platformOrigin}, the value of {@code
 * qits.egress.platform.origin}); it answers 200 and records what it received.
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
  static final String EXCHANGES = "qits.test.suite-idp.exchanges";
  static final String EXCHANGE_REFUSAL = "qits.test.suite-idp.exchange-refusal";
  static final String EXCHANGE_LIFE = "qits.test.suite-idp.exchange-life";
  static final String EXCHANGE_AUTHORIZATION = "qits.test.suite-idp.exchange-authorization";
  static final String PLATFORM_CALLS = "qits.test.suite-platform.calls";
  static final String PLATFORM_URI = "qits.test.suite-platform.uri";
  static final String PLATFORM_AUTHORIZATION = "qits.test.suite-platform.authorization";
  static final String PLATFORM_LEAKED = "qits.test.suite-platform.leaked";

  static final String TOKEN_EXCHANGE = "urn:ietf:params:oauth:grant-type:token-exchange";

  private static final ObjectMapper JSON = new ObjectMapper();

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
        server.createContext(
            "/idp/token",
            exchange -> {
              try {
                exchange(exchange);
              } catch (Throwable failure) {
                // A handler that throws closes the connection with no word; say why instead.
                failure.printStackTrace();
                answer(exchange, 500, "{\"error\":\"suite idp: " + failure + "\"}");
              }
            });
        server.createContext(
            "/platform/",
            exchange -> {
              exchange.getRequestBody().readAllBytes();
              System.setProperty(
                  PLATFORM_CALLS, String.valueOf(Integer.getInteger(PLATFORM_CALLS, 0) + 1));
              System.setProperty(PLATFORM_URI, exchange.getRequestURI().toString());
              String authorization = exchange.getRequestHeaders().getFirst("Authorization");
              System.setProperty(PLATFORM_AUTHORIZATION, authorization == null ? "" : authorization);
              List<String> leaked = new ArrayList<>();
              for (String name : exchange.getRequestHeaders().keySet()) {
                String lower = name.toLowerCase(java.util.Locale.ROOT);
                if (lower.equals("cookie") || lower.startsWith("x-qits-") || lower.equals("x-api-key")) {
                  leaked.add(lower);
                }
              }
              System.setProperty(PLATFORM_LEAKED, String.join(",", leaked));
              answer(exchange, 200, "{\"platform\":\"answered\"}");
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

  /** {@code qits.egress.platform.origin} in the suites: this server's {@code /platform/{label}}. */
  public static String platformOrigin() {
    String idp = ensureStarted();
    return idp.substring(0, idp.length() - "/idp".length()) + "/platform/{label}";
  }

  /**
   * The exchange: {@code grant_type} token-exchange, the asking client by Basic, the subject a JWT
   * whose claims are copied, an {@code act} subject refused (no chains) — or the refusal a test set.
   */
  private static void exchange(HttpExchange exchange) throws IOException {
    String body = new String(exchange.getRequestBody().readAllBytes(), StandardCharsets.UTF_8);
    System.setProperty(EXCHANGES, String.valueOf(Integer.getInteger(EXCHANGES, 0) + 1));
    Map<String, String> form = new HashMap<>();
    for (String pair : body.split("&")) {
      int eq = pair.indexOf('=');
      if (eq > 0) {
        form.put(
            URLDecoder.decode(pair.substring(0, eq), StandardCharsets.UTF_8),
            URLDecoder.decode(pair.substring(eq + 1), StandardCharsets.UTF_8));
      }
    }
    String authorization = exchange.getRequestHeaders().getFirst("Authorization");
    System.setProperty(EXCHANGE_AUTHORIZATION, authorization == null ? "" : authorization);
    if (!TOKEN_EXCHANGE.equals(form.get("grant_type"))) {
      answer(exchange, 400, "{\"error\":\"unsupported_grant_type\"}");
      return;
    }
    String refusal = System.getProperty(EXCHANGE_REFUSAL);
    if (refusal != null && !refusal.isEmpty()) {
      answer(exchange, 400, "{\"error\":\"" + refusal + "\"}");
      return;
    }
    String actor = basicUser(authorization);
    if (actor == null) {
      answer(exchange, 400, "{\"error\":\"unauthorized_client\"}");
      return;
    }
    // Jackson, not Vert.x' JsonObject: this class may live in a loader whose Vert.x JSON factory is
    // Quarkus' and does not load here.
    JsonNode subject;
    try {
      String[] parts = form.getOrDefault("subject_token", "").split("\\.");
      subject = JSON.readTree(Base64.getUrlDecoder().decode(parts[1]));
    } catch (RuntimeException | IOException notAJwt) {
      answer(exchange, 400, "{\"error\":\"invalid_grant\"}");
      return;
    }
    if (subject.has("act")) {
      answer(exchange, 400, "{\"error\":\"invalid_grant\"}");
      return;
    }
    List<String> groups = new ArrayList<>();
    subject.path("groups").forEach(group -> groups.add(group.asText()));
    long life = Long.getLong(EXCHANGE_LIFE, 300L);
    String minted =
        MockIdp.ensureStarted()
            .token()
            .subject(subject.path("sub").asText())
            .audience("qits-platform")
            .groups(groups.toArray(String[]::new))
            .claim("act", Map.of("sub", actor))
            .mint();
    answer(
        exchange,
        200,
        JSON.writeValueAsString(
            Map.of(
                "access_token", minted,
                "issued_token_type", "urn:ietf:params:oauth:token-type:access_token",
                "token_type", "Bearer",
                "expires_in", life)));
  }

  /** The user of a Basic header, or null. */
  private static String basicUser(String authorization) {
    if (authorization == null || !authorization.startsWith("Basic ")) {
      return null;
    }
    String pair =
        new String(
            Base64.getDecoder().decode(authorization.substring("Basic ".length())),
            StandardCharsets.UTF_8);
    int colon = pair.indexOf(':');
    return colon <= 0 ? null : pair.substring(0, colon);
  }

  /** How many exchanges were asked in this JVM. */
  public static int exchanges() {
    return Integer.getInteger(EXCHANGES, 0);
  }

  /** The {@code Authorization} the last exchange carried: this service's own Basic pair. */
  public static String lastExchangeAuthorization() {
    return System.getProperty(EXCHANGE_AUTHORIZATION);
  }

  /** Refuse every exchange from now with this OAuth error, or null to exchange again. */
  public static void refuseExchanges(String error) {
    if (error == null) {
      System.clearProperty(EXCHANGE_REFUSAL);
    } else {
      System.setProperty(EXCHANGE_REFUSAL, error);
    }
  }

  /** The {@code expires_in} exchanged tokens are handed out with (300 unless set). */
  public static void exchangeLife(long seconds) {
    System.setProperty(EXCHANGE_LIFE, String.valueOf(seconds));
  }

  /** How many calls the suites' platform service received. */
  public static int platformCalls() {
    return Integer.getInteger(PLATFORM_CALLS, 0);
  }

  /** The request target the platform service last received. */
  public static String platformUri() {
    return System.getProperty(PLATFORM_URI);
  }

  /** The {@code Authorization} the platform service last received. */
  public static String platformAuthorization() {
    return System.getProperty(PLATFORM_AUTHORIZATION);
  }

  /** Caller headers the platform service last received that must never arrive, comma-joined. */
  public static String platformLeaked() {
    return System.getProperty(PLATFORM_LEAKED);
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
