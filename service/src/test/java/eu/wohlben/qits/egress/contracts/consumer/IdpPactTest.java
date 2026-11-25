package eu.wohlben.qits.egress.contracts.consumer;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import eu.wohlben.qits.pact.consumer.ConsumerPact;
import eu.wohlben.qits.pact.consumer.GoldenInteraction;
import eu.wohlben.qits.pact.consumer.GoldenMasters;
import eu.wohlben.qits.pact.consumer.Trigger;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import org.jose4j.jwk.JsonWebKey;
import org.jose4j.jwk.JsonWebKeySet;
import org.jose4j.jwk.RsaJsonWebKey;
import org.junit.jupiter.api.Test;

/**
 * <b>What this service asks qits-idp-service</b>:
 *
 * <ul>
 *   <li>the two reads quarkus-oidc makes when the machine-auth gate turns the tenant on — the
 *       discovery document, then the JWKS at its {@code jwks_uri} (rows here);
 *   <li>the client-credentials mint of the named client {@code qits}, spent by qits-telemetry-core's
 *       exporters ({@code IdpTokenMintPactTest} runs it through the real oidc client).
 * </ul>
 *
 * <p>The proxy's own idp calls (introspection, qits-2620; token exchange, qits-2623) join this pact
 * with the code that makes them.
 *
 * <p>The pact is {@code pacts/qits-egress-service_qits-idp-service.json}; {@code
 * -Dgolden.update=true} rewrites it.
 */
class IdpPactTest {

  static final String CONSUMER = "qits-egress-service";

  static final GoldenMasters IDP = GoldenMasters.of("qits-idp-service", "qits-idp");

  static final String STATE = "a published signing key";

  static final Trigger STARTUP = Trigger.event("StartupEvent");

  /** The issuer is bound exactly: a different value fails every token. */
  static final GoldenInteraction DISCOVERY =
      GoldenInteraction.of(STARTUP, STATE, "getOpenIdConfiguration")
          .consumes("issuer", "jwks_uri", "token_endpoint")
          .exact("issuer");

  /** The JWKS: at least one key, each with what quarkus-oidc needs to build and pick it. */
  static final GoldenInteraction JWKS =
      GoldenInteraction.of(STARTUP, STATE, "getJwks")
          .consumes("keys[].kid", "keys[].kty", "keys[].n", "keys[].e", "keys[].alg", "keys[].use");

  /** The qits-idp state that records the client-credentials mint of a service client. */
  static final String A_SERVICE_CLIENT_CALLING_ITS_PEERS = "a service client calling its peers";

  /** The mint, caused by whichever call needs this service's bearer first. */
  static final GoldenInteraction MINT =
      GoldenInteraction.of(
              Trigger.of("call", "call", "qits-telemetry-core (OTLP export)"),
              A_SERVICE_CLIENT_CALLING_ITS_PEERS,
              "issueToken")
          .header("Authorization", "{authorization}")
          .consumes("access_token", "expires_in");

  static final ConsumerPact PACT = ConsumerPact.of(CONSUMER, IDP, MINT, DISCOVERY, JWKS);

  private static final ObjectMapper JSON = new ObjectMapper();

  @Test
  void quarkusOidcReadsTheDiscoveryDocument() {
    PACT.run(DISCOVERY, (url, recorded) -> {
      JsonNode doc = JSON.readTree(get(url + recorded.path()));
      assertTrue(doc.path("issuer").isTextual(), "issuer: " + doc);
      URI.create(doc.path("jwks_uri").asText());
      URI.create(doc.path("token_endpoint").asText());
    });
  }

  @Test
  void quarkusOidcFindsThePublishedSigningKey() {
    PACT.run(JWKS, (url, recorded) -> {
      JsonWebKeySet keys = new JsonWebKeySet(get(url + recorded.path()));
      JsonWebKey key =
          keys.findJsonWebKey(recorded.params().get("kid"), RsaJsonWebKey.KEY_TYPE, "sig", "RS256");
      assertNotNull(key, () -> "an RSA signing key for RS256 named by the state's kid in " + keys.getJsonWebKeys());
      assertNotNull(((RsaJsonWebKey) key).getRsaPublicKey().getModulus());
    });
  }

  @Test
  void theCommittedPactIsWhatTheRowsWrite() {
    PACT.compareOrWritePactFile();
  }

  @Test
  void everyInteractionCarriesBothReferences() {
    PACT.assertEveryInteractionCarriesBothReferences();
    assertTrue(PACT.unrecorded().isEmpty(), "every row is recorded: " + PACT.unrecorded());
    assertEquals(PACT.rows().size(), PACT.recorded().size());
  }

  private static String get(String url) throws Exception {
    HttpResponse<String> answer = HttpClient.newHttpClient().send(
        HttpRequest.newBuilder(URI.create(url)).header("Accept", "application/json").build(),
        HttpResponse.BodyHandlers.ofString());
    assertEquals(200, answer.statusCode(), answer.body());
    return answer.body();
  }
}
