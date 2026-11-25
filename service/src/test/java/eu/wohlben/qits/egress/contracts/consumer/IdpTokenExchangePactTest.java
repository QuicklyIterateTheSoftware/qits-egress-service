package eu.wohlben.qits.egress.contracts.consumer;

import static org.junit.jupiter.api.Assertions.assertEquals;

import eu.wohlben.qits.egress.identity.IdpTokenExchange;
import eu.wohlben.qits.pact.consumer.GoldenInteraction;
import io.vertx.core.Vertx;
import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.Map;
import java.util.concurrent.TimeUnit;
import org.junit.jupiter.api.Test;

/**
 * <b>A platform route's token exchange at qits-idp</b> (qits-2623), driven through the real {@link
 * IdpTokenExchange} against a pact mock server: configured with the Basic pair the state's {@code
 * authorization} encodes and exchanging the state's {@code subjectToken}, so the form body on the
 * wire is exactly the one idp recorded.
 */
class IdpTokenExchangePactTest {

  @Test
  void aPersonsTokenIsExchanged() {
    exchanged(IdpPactTest.EXCHANGE_PERSON);
  }

  @Test
  void aCommissionedTokenIsExchanged() {
    exchanged(IdpPactTest.EXCHANGE_COMMISSIONED);
  }

  @Test
  void aClientThatIsNoActorIsRefused() {
    IdpPactTest.PACT.run(
        IdpPactTest.EXCHANGE_NOT_ACTOR,
        (url, recorded) -> assertEquals(400, exchange(url, recorded.params()).status()));
  }

  @Test
  void anExchangedTokenIsNotExchangedAgain() {
    IdpPactTest.PACT.run(
        IdpPactTest.EXCHANGE_CHAINED,
        (url, recorded) -> assertEquals(400, exchange(url, recorded.params()).status()));
  }

  private static void exchanged(GoldenInteraction row) {
    IdpPactTest.PACT.run(
        row,
        (url, recorded) -> {
          IdpTokenExchange.Answer answer = exchange(url, recorded.params());
          assertEquals(200, answer.status(), answer.body());
          IdpTokenExchange.Exchanged read = IdpTokenExchange.Exchanged.of(answer.body());
          var golden = IdpPactTest.IDP.json(row.state(), row.operationId());
          assertEquals(golden.path("access_token").asText(), read.accessToken());
          assertEquals(golden.path("expires_in").asLong(), read.expiresIn());
        });
  }

  /** One exchange through a client at the mock's {@code /idp}, with the state's Basic pair. */
  private static IdpTokenExchange.Answer exchange(String url, Map<String, String> params)
      throws Exception {
    String[] pair =
        new String(
                Base64.getDecoder()
                    .decode(params.get("authorization").substring("Basic ".length())),
                StandardCharsets.UTF_8)
            .split(":", 2);
    Vertx vertx = Vertx.vertx();
    try {
      return new IdpTokenExchange(vertx.createHttpClient(), url + "/idp", pair[0], pair[1], 10_000)
          .exchange(params.get("subjectToken"))
          .toCompletionStage()
          .toCompletableFuture()
          .get(20, TimeUnit.SECONDS);
    } finally {
      vertx.close();
    }
  }
}
