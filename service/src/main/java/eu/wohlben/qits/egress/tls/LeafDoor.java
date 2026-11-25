package eu.wohlben.qits.egress.tls;

import io.vertx.core.Future;
import io.vertx.core.Vertx;
import io.vertx.core.http.HttpClient;
import io.vertx.core.http.HttpHeaders;
import io.vertx.core.http.HttpMethod;
import io.vertx.core.http.RequestOptions;
import io.vertx.core.json.DecodeException;
import io.vertx.core.json.JsonObject;
import java.security.GeneralSecurityException;
import java.security.cert.X509Certificate;
import java.time.Instant;
import java.time.format.DateTimeParseException;
import java.util.Optional;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.CompletionStage;
import java.util.function.Supplier;

/**
 * The one dial this process makes at qits-certificates: {@code POST <certificates-url>/api/leaves}
 * with {@code {"csr": "<PKCS#10 PEM>"}} and this service's own {@code qits} bearer, answered 201
 * {@code {"certificate","chain","serial","notAfter","anchorId"}} — and the {@link LeafIssuer} built
 * on it: a fresh key, its CSR, the call, the chain checked against the key.
 *
 * <p>The answer is read through Vert.x's {@link JsonObject}, a tree, not bound to a record: there
 * is no type here for the native image to reflect on.
 *
 * <p>Each call is bounded, connection included. A refusal is a failed stage carrying the status
 * ({@link LeafIssueFailed}); the caller decides about retrying.
 */
public final class LeafDoor implements LeafIssuer {

  /** What qits-certificates answered, whatever its status. */
  public record Answer(int status, String body) {}

  /** The fields of a 201. */
  public record Issued(String certificate, String chain, String serial, Instant notAfter, String anchorId) {

    /** Read a 201's body; a field missing or malformed fails naming it. */
    public static Issued of(String body) {
      JsonObject json;
      try {
        json = new JsonObject(body);
      } catch (DecodeException e) {
        throw new IllegalArgumentException("the answer is not a JSON object");
      }
      String notAfter = json.getString("notAfter");
      if (json.getString("certificate") == null || notAfter == null) {
        throw new IllegalArgumentException("the answer names no certificate or no notAfter");
      }
      try {
        return new Issued(
            json.getString("certificate"),
            json.getString("chain"),
            json.getString("serial"),
            Instant.parse(notAfter),
            json.getString("anchorId"));
      } catch (DateTimeParseException e) {
        throw new IllegalArgumentException("the answer's notAfter is not an instant");
      }
    }
  }

  private final Vertx vertx;

  private final HttpClient client;

  private final String endpoint;

  private final Supplier<CompletionStage<Optional<String>>> bearer;

  private final long timeoutMs;

  /**
   * @param client a small client of its own, never the proxy's
   * @param certificatesUrl the base, ending in {@code /certificates}
   * @param bearer this service's own access token, empty when it holds no client
   * @param timeoutMs the bound on each call, connection included
   */
  public LeafDoor(
      Vertx vertx,
      HttpClient client,
      String certificatesUrl,
      Supplier<CompletionStage<Optional<String>>> bearer,
      long timeoutMs) {
    this.vertx = vertx;
    this.client = client;
    String base = certificatesUrl;
    while (base.endsWith("/")) {
      base = base.substring(0, base.length() - 1);
    }
    this.endpoint = base + "/api/leaves";
    this.bearer = bearer;
    this.timeoutMs = timeoutMs;
  }

  /** The door it asks. */
  public String endpoint() {
    return endpoint;
  }

  /** One {@code POST /api/leaves} of {@code csrPem}, under {@code authorization}. */
  public Future<Answer> post(String authorization, String csrPem) {
    RequestOptions options =
        new RequestOptions()
            .setMethod(HttpMethod.POST)
            .setAbsoluteURI(endpoint)
            .setConnectTimeout(timeoutMs)
            .setTimeout(timeoutMs);
    return client
        .request(options)
        .compose(
            request -> {
              request.putHeader(HttpHeaders.AUTHORIZATION, authorization);
              request.putHeader(HttpHeaders.CONTENT_TYPE, "application/json");
              request.putHeader(HttpHeaders.ACCEPT, "application/json");
              return request.send(new JsonObject().put("csr", csrPem).encode());
            })
        .compose(
            response ->
                response.body().map(body -> new Answer(response.statusCode(), body.toString())));
  }

  @Override
  public CompletionStage<Leaf> issue(String host) {
    return bearer
        .get()
        .thenCompose(
            token -> {
              if (token.isEmpty()) {
                return CompletableFuture.failedFuture(
                    new LeafIssueFailed(
                        0, "this process holds no qits client token to ask for a leaf with"));
              }
              // Key generation off the event loop; the key stays in this closure and the Leaf.
              return vertx
                  .executeBlocking(() -> LeafKeys.request(host), false)
                  .compose(request -> post("Bearer " + token.get(), request.csrPem())
                      .map(answer -> leaf(request, answer)))
                  .toCompletionStage();
            });
  }

  /** The leaf a 201 makes of {@code request}, or the failure any other answer is. */
  static Leaf leaf(LeafKeys.Request request, Answer answer) {
    if (answer.status() != 201) {
      throw new LeafIssueFailed(answer.status(), refusal(answer.body()));
    }
    try {
      Issued issued = Issued.of(answer.body());
      X509Certificate[] chain =
          LeafKeys.certificates(issued.chain() != null ? issued.chain() : issued.certificate());
      LeafKeys.check(request, chain);
      X509Certificate leaf = chain[0];
      return new Leaf(
          request.host(),
          request.keys().getPrivate(),
          chain,
          issued.serial() != null ? issued.serial() : leaf.getSerialNumber().toString(16),
          leaf.getNotBefore().toInstant(),
          leaf.getNotAfter().toInstant(),
          issued.anchorId());
    } catch (GeneralSecurityException | IllegalArgumentException e) {
      throw new LeafIssueFailed(answer.status(), "unusable answer: " + e.getMessage());
    }
  }

  /** The {@code error} of a refusal, reduced to a safe alphabet; the body itself is never logged. */
  static String refusal(String body) {
    String error = null;
    try {
      error = new JsonObject(body).getString("error");
    } catch (RuntimeException e) {
      // not JSON: the status says enough
    }
    if (error == null) {
      return "refused";
    }
    String safe = error.replaceAll("[^A-Za-z0-9 ._:-]", "?");
    return safe.length() > 80 ? safe.substring(0, 80) : safe;
  }
}
