package eu.wohlben.qits.egress.contracts.consumer;

import static org.junit.jupiter.api.Assertions.assertEquals;

import eu.wohlben.qits.egress.identity.IdpIntrospection;
import io.vertx.core.Vertx;
import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.Map;
import java.util.concurrent.TimeUnit;
import org.junit.jupiter.api.Test;

/**
 * <b>The proxy listener's token introspection at qits-idp</b>, driven through the real {@link
 * IdpIntrospection} against a pact mock server: configured with the Basic pair the state's {@code
 * authorization} encodes, so what goes on the wire is exactly the header the provider's state
 * answers, and the body {@code {"token": …}} it records.
 */
class IdpIntrospectionPactTest {

  @Test
  void aLiveTokenStandsForAJwt() {
    IdpPactTest.PACT.run(
        IdpPactTest.INTROSPECT,
        (url, recorded) -> {
          IdpIntrospection.Answer answer = introspect(url, recorded.params());
          assertEquals(200, answer.status(), answer.body());
          IdpIntrospection.Introspected read = IdpIntrospection.Introspected.of(answer.body());
          var golden =
              IdpPactTest.IDP.json(
                  IdpPactTest.INTROSPECT.state(), IdpPactTest.INTROSPECT.operationId());
          assertEquals(golden.path("accessToken").asText(), read.accessToken());
          assertEquals(golden.path("expiresIn").asLong(), read.expiresIn());
        });
  }

  @Test
  void aDeletedTokenIsRefused() {
    IdpPactTest.PACT.run(
        IdpPactTest.INTROSPECT_DELETED,
        (url, recorded) -> assertEquals(404, introspect(url, recorded.params()).status()));
  }

  /** One introspection through a client at the mock's {@code /idp}, with the state's Basic pair. */
  private static IdpIntrospection.Answer introspect(String url, Map<String, String> params)
      throws Exception {
    String[] pair =
        new String(
                Base64.getDecoder()
                    .decode(params.get("authorization").substring("Basic ".length())),
                StandardCharsets.UTF_8)
            .split(":", 2);
    Vertx vertx = Vertx.vertx();
    try {
      return new IdpIntrospection(vertx.createHttpClient(), url + "/idp", pair[0], pair[1], 10_000)
          .introspect(params.get("token"))
          .toCompletionStage()
          .toCompletableFuture()
          .get(20, TimeUnit.SECONDS);
    } finally {
      vertx.close();
    }
  }
}
