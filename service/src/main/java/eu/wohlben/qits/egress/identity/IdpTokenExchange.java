package eu.wohlben.qits.egress.identity;

import io.vertx.core.Future;
import io.vertx.core.http.HttpClient;
import io.vertx.core.http.HttpHeaders;
import io.vertx.core.http.HttpMethod;
import io.vertx.core.http.RequestOptions;
import io.vertx.core.json.JsonObject;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;

/**
 * <b>The RFC 8693 token exchange at qits-idp</b> (qits-2613): {@code POST <idp>/token} with this
 * service's own Basic client pair, swapping a caller's bearer for a JWT that names the caller as
 * its {@code sub} and this service as its actor ({@code act.sub}), for a platform route's target.
 *
 * <pre>
 * grant_type=urn:ietf:params:oauth:grant-type:token-exchange
 * subject_token=&lt;the caller's JWT, or its qits_tok_&gt;
 * subject_token_type=urn:ietf:params:oauth:token-type:access_token
 * </pre>
 *
 * <p>idp answers {@code {access_token, issued_token_type, token_type, expires_in}}, or 400 {@code
 * unauthorized_client} for a client that is not an exchange actor and {@code invalid_grant} for a
 * subject it will not exchange (an exchanged one included: exchanges do not chain). The rows are in
 * {@code IdpPactTest}: {@code EXCHANGE_PERSON}, {@code EXCHANGE_COMMISSIONED}, {@code
 * EXCHANGE_NOT_ACTOR}, {@code EXCHANGE_CHAINED}.
 */
public final class IdpTokenExchange {

  static final String GRANT_TYPE = "urn:ietf:params:oauth:grant-type:token-exchange";

  static final String ACCESS_TOKEN_TYPE = "urn:ietf:params:oauth:token-type:access_token";

  /** What idp answered, whatever its status. */
  public record Answer(int status, String body) {}

  /** The fields of a 200 the gateway reads. */
  public record Exchanged(String accessToken, long expiresIn) {

    /** Read a 200's body. */
    public static Exchanged of(String body) {
      JsonObject json = new JsonObject(body);
      Number life = json.getNumber("expires_in");
      return new Exchanged(json.getString("access_token"), life == null ? 0 : life.longValue());
    }
  }

  private final HttpClient client;

  private final String endpoint;

  private final String authorization;

  private final long timeoutMs;

  /**
   * @param client a small client of its own, never the proxy's
   * @param idpUrl the idp's base, ending in {@code /idp}: the same base the oidc client mints at
   * @param clientId this service's idp client id, {@code ${QITS_ENVIRONMENT}-qits-egress}
   * @param clientSecret its secret; null or blank when the deployment holds none
   * @param timeoutMs the bound on each call, connection included
   */
  public IdpTokenExchange(
      HttpClient client, String idpUrl, String clientId, String clientSecret, long timeoutMs) {
    this.client = client;
    this.endpoint = IdpKeys.trimmed(idpUrl) + "/token";
    this.authorization = IdpIntrospection.basicAuthorization(clientId, clientSecret);
    this.timeoutMs = timeoutMs;
  }

  /** Whether this process holds a client to exchange with. */
  public boolean hasCredential() {
    return authorization != null;
  }

  /** The form body for one subject; the static values spelled exactly as idp's recording has them. */
  static String form(String subjectToken) {
    return "grant_type="
        + GRANT_TYPE
        + "&subject_token="
        + URLEncoder.encode(subjectToken, StandardCharsets.UTF_8)
        + "&subject_token_type="
        + ACCESS_TOKEN_TYPE;
  }

  /**
   * Exchange one caller's bearer.
   *
   * @param subjectToken the caller's raw bearer, sent in the body and nowhere else
   */
  public Future<Answer> exchange(String subjectToken) {
    if (authorization == null) {
      return Future.failedFuture(
          new IllegalStateException("this process holds no idp client to exchange with"));
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
              request.putHeader(HttpHeaders.CONTENT_TYPE, "application/x-www-form-urlencoded");
              request.putHeader(HttpHeaders.ACCEPT, "application/json");
              return request.send(form(subjectToken));
            })
        .compose(
            response ->
                response.body().map(body -> new Answer(response.statusCode(), body.toString())));
  }
}
