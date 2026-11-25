package eu.wohlben.qits.egress.identity;

import io.vertx.core.Future;
import io.vertx.core.http.HttpClient;
import io.vertx.core.http.HttpHeaders;
import io.vertx.core.http.HttpMethod;
import io.vertx.core.http.RequestOptions;
import io.vertx.core.json.JsonObject;
import java.nio.charset.StandardCharsets;
import java.util.Base64;

/**
 * The one dial this process makes at qits-idp's {@code POST /api/tokens/introspect}: an opaque
 * {@code qits_tok_…} in, the ordinary JWT it currently stands for out — qits-edge's {@code
 * IdpIntrospection}, reduced to the token door.
 *
 * <p><b>The credential is this service's own idp client</b> ({@code QITS_RESOURCE_IDP_CLIENT_ID} /
 * {@code _SECRET}, the {@code idp:client} resource), in HTTP Basic. It is what makes introspection
 * a privilege rather than an oracle. Absent (a clone, a suite) is an ordinary state: {@link
 * #hasCredential()} says so and every opaque token is refused.
 *
 * <p>Each call is bounded, connection included. An ANSWER is never retried — idp saying no is idp
 * deciding — and an unreachable idp is a failed future, which the gateway answers 503 rather than
 * 401: nothing was learnt about the token.
 */
public final class IdpIntrospection {

  /** What idp answered, whatever its status. */
  public record Answer(int status, String body) {}

  /** The fields of a 200 the gateway reads: the JWT the token stands for and its remaining life. */
  public record Introspected(String accessToken, long expiresIn) {

    /** Read a 200's body. */
    public static Introspected of(String body) {
      JsonObject json = new JsonObject(body);
      Number life = json.getNumber("expiresIn");
      return new Introspected(json.getString("accessToken"), life == null ? 0 : life.longValue());
    }
  }

  private final HttpClient client;

  private final String endpoint;

  private final String authorization;

  private final long timeoutMs;

  /**
   * @param client a small client of its own, never the proxy's
   * @param idpUrl the idp's base, ending in {@code /idp}
   * @param clientId this service's idp client id
   * @param clientSecret its secret; null or blank when the deployment holds none
   * @param timeoutMs the bound on each call, connection included
   */
  public IdpIntrospection(
      HttpClient client, String idpUrl, String clientId, String clientSecret, long timeoutMs) {
    this.client = client;
    this.endpoint = IdpKeys.trimmed(idpUrl) + "/api/tokens/introspect";
    this.authorization = basicAuthorization(clientId, clientSecret);
    this.timeoutMs = timeoutMs;
  }

  /** {@code Basic base64(<id>:<secret>)}, or null when either half is missing. */
  static String basicAuthorization(String clientId, String clientSecret) {
    if (clientId == null || clientId.isBlank() || clientSecret == null || clientSecret.isBlank()) {
      return null;
    }
    return "Basic "
        + Base64.getEncoder()
            .encodeToString((clientId + ":" + clientSecret).getBytes(StandardCharsets.UTF_8));
  }

  /** Whether this process holds a client to introspect with. */
  public boolean hasCredential() {
    return authorization != null;
  }

  /** The door it asks. */
  public String endpoint() {
    return endpoint;
  }

  /**
   * Ask idp what one token stands for.
   *
   * @param token sent as the body's {@code token} and nowhere else
   */
  public Future<Answer> introspect(String token) {
    if (authorization == null) {
      return Future.failedFuture(
          new IllegalStateException("this process holds no idp client to introspect with"));
    }
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
              return request.send(new JsonObject().put("token", token).encode());
            })
        .compose(
            response ->
                response.body().map(body -> new Answer(response.statusCode(), body.toString())));
  }
}
