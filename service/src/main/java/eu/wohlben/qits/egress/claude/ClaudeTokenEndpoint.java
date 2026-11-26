package eu.wohlben.qits.egress.claude;

import eu.wohlben.qits.egress.store.ClaudeCredentialStore.Rotation;
import io.vertx.core.Future;
import io.vertx.core.buffer.Buffer;
import io.vertx.core.http.HttpClient;
import io.vertx.core.http.HttpClientResponse;
import io.vertx.core.http.HttpHeaders;
import io.vertx.core.http.HttpMethod;
import io.vertx.core.http.RequestOptions;
import io.vertx.core.json.DecodeException;
import io.vertx.core.json.JsonObject;
import java.time.Instant;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;

/**
 * <b>The one call that refreshes the held Claude login</b>: {@code POST
 * qits.egress.claude.token-url} ({@code https://platform.claude.com/v1/oauth/token}) with {@code
 * Content-Type: application/json} and {@code {"grant_type":"refresh_token","refresh_token":<held>,
 * "client_id":<qits.egress.claude.client-id>}} — what Claude Code itself sends. A 200 carries {@code
 * access_token}, the rotated {@code refresh_token}, {@code expires_in} (seconds) and {@code scope}.
 *
 * <p>A third party's door, so no pact. The answer is read as a Vert.x {@link JsonObject} tree: no
 * type for the native image to reflect on. <b>Nothing of a body reaches a log or an error</b>: a
 * failure is a fixed text naming the status or the kind of failure, which is what lands in {@code
 * last_refresh_error} and the WARN.
 */
public final class ClaudeTokenEndpoint {

  private final HttpClient client;

  private final String tokenUrl;

  private final String clientId;

  private final long timeoutMs;

  /**
   * @param client a small client of its own, never the proxy's
   * @param tokenUrl the absolute URL of the token door
   * @param clientId Claude Code's OAuth client id
   * @param timeoutMs the bound on the call, connection included
   */
  public ClaudeTokenEndpoint(HttpClient client, String tokenUrl, String clientId, long timeoutMs) {
    this.client = client;
    this.tokenUrl = tokenUrl;
    this.clientId = clientId;
    this.timeoutMs = timeoutMs;
  }

  /** Refresh with {@code refreshToken}. Blocking: never on an event loop. */
  public Rotation refresh(String refreshToken, Instant now) {
    String body =
        new JsonObject()
            .put("grant_type", "refresh_token")
            .put("refresh_token", refreshToken)
            .put("client_id", clientId)
            .encode();
    Answer answer;
    try {
      answer =
          client
              .request(
                  new RequestOptions()
                      .setMethod(HttpMethod.POST)
                      .setAbsoluteURI(tokenUrl)
                      .setTimeout(timeoutMs)
                      .setConnectTimeout(timeoutMs))
              .compose(
                  request ->
                      request
                          .putHeader(HttpHeaders.CONTENT_TYPE, "application/json")
                          .putHeader(HttpHeaders.ACCEPT, "application/json")
                          .send(Buffer.buffer(body)))
              .compose(ClaudeTokenEndpoint::read)
              .toCompletionStage()
              .toCompletableFuture()
              .get(timeoutMs + 1_000, TimeUnit.MILLISECONDS);
    } catch (InterruptedException e) {
      Thread.currentThread().interrupt();
      return Rotation.failed("interrupted");
    } catch (TimeoutException e) {
      return Rotation.failed("the token endpoint did not answer in time");
    } catch (ExecutionException e) {
      return Rotation.failed(
          "the token endpoint cannot be reached: " + e.getCause().getClass().getSimpleName());
    }
    return rotation(answer, now);
  }

  /** What the token door answered, whatever its status. */
  record Answer(int status, String body) {}

  private static Future<Answer> read(HttpClientResponse response) {
    return response.body().map(buffer -> new Answer(response.statusCode(), buffer.toString()));
  }

  /** A 200's rotated pair, or the failure in a fixed text. Package-private for the tests. */
  static Rotation rotation(Answer answer, Instant now) {
    if (answer.status() != 200) {
      return Rotation.failed("the token endpoint answered " + answer.status());
    }
    JsonObject json;
    try {
      json = new JsonObject(answer.body());
    } catch (DecodeException | ClassCastException e) {
      return Rotation.failed("the token endpoint answered no JSON object");
    }
    Object access = json.getValue("access_token");
    Object expiresIn = json.getValue("expires_in");
    if (!(access instanceof String accessToken) || accessToken.isBlank()) {
      return Rotation.failed("the token endpoint answered no access_token");
    }
    if (!(expiresIn instanceof Number seconds) || seconds.longValue() <= 0) {
      return Rotation.failed("the token endpoint answered no expires_in");
    }
    Object refresh = json.getValue("refresh_token");
    Object scope = json.getValue("scope");
    return new Rotation(
        accessToken,
        refresh instanceof String rotated && !rotated.isBlank() ? rotated : null,
        now.plusSeconds(seconds.longValue()),
        scope instanceof String scopes && !scopes.isBlank() ? scopes : null,
        null);
  }
}
