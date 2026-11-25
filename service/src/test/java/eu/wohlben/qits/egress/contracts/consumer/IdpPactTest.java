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
import au.com.dius.pact.core.model.DefaultPactWriter;
import au.com.dius.pact.core.model.Interaction;
import au.com.dius.pact.core.model.PactSpecVersion;
import au.com.dius.pact.core.model.V4Pact;
import au.com.dius.pact.core.model.generators.Category;
import au.com.dius.pact.core.model.generators.GeneratorTestMode;
import au.com.dius.pact.core.model.generators.ProviderStateGenerator;
import au.com.dius.pact.core.support.expressions.DataType;
import eu.wohlben.qits.pact.consumer.GoldenFiles;
import java.io.PrintWriter;
import java.io.StringWriter;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import java.util.Map;
import java.util.Set;
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
 * <p>The proxy listener's own idp calls (qits-2620): its caller identity reads the same discovery
 * document and JWKS (the rows above serve both), and introspects an opaque {@code qits_tok_} caller
 * with this service's own Basic pair — {@link #INTROSPECT} and {@link #INTROSPECT_DELETED}, run by
 * {@code IdpIntrospectionPactTest}; a platform route exchanges the caller's bearer (qits-2623) —
 * {@link #EXCHANGE_PERSON}, {@link #EXCHANGE_COMMISSIONED}, {@link #EXCHANGE_NOT_ACTOR} and {@link
 * #EXCHANGE_CHAINED}, run by {@code IdpTokenExchangePactTest}.
 *
 * <p><b>The exchange rows name their subject token by provider state.</b> idp's exchange states
 * mint a fresh subject token per verification (a JWT, a {@code qits_tok_}), recorded frozen to
 * zeros, and the token travels in a FORM body, which the pact library inlines verbatim. So {@link
 * #pactWithStateTokens} adds a provider-state generator {@code $.subject_token = ${subjectToken}}
 * to those rows' request bodies — the {@code Authorization} header already carries {@code
 * ${authorization}} — and {@link #theCommittedPactIsWhatTheRowsWrite} writes that pact rather than
 * the library's own, or the provider would be asked to exchange a string of zeros.
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

  /** What makes the proxy listener ask: a caller presenting an opaque token. */
  static final Trigger OPAQUE_CALLER =
      Trigger.of("call", "call", "the proxy listener (8081): a caller presenting qits_tok_");

  /** The qits-idp state of a live commissioned token, asked about with a client's Basic pair. */
  static final String A_COMMISSIONED_TOKEN = "a commissioned token";

  /** The same token after its deletion: idp's 404. */
  static final String A_COMMISSIONED_TOKEN_THAT_WAS_DELETED = "a commissioned token that was deleted";

  /** The token stands for a JWT, with its remaining life. */
  static final GoldenInteraction INTROSPECT =
      GoldenInteraction.of(OPAQUE_CALLER, A_COMMISSIONED_TOKEN, "introspectToken")
          .header("Authorization", "{authorization}")
          .consumes("accessToken", "expiresIn");

  /** A deleted token: the status is the whole verdict, the body is not read. */
  static final GoldenInteraction INTROSPECT_DELETED =
      GoldenInteraction.of(OPAQUE_CALLER, A_COMMISSIONED_TOKEN_THAT_WAS_DELETED, "introspectToken")
          .header("Authorization", "{authorization}");

  /** What makes the proxy listener exchange a bearer: a call on a platform route. */
  static final Trigger PLATFORM_CALLER =
      Trigger.of("call", "call", "the proxy listener (8081): a platform route");

  static final String EXCHANGING_A_PERSONS_TOKEN = "a token-exchange actor exchanging a person's token";

  static final String EXCHANGING_A_COMMISSIONED_TOKEN =
      "a token-exchange actor exchanging a commissioned token";

  static final String NO_EXCHANGE_ACTOR = "a client that is no token-exchange actor";

  static final String EXCHANGING_AN_EXCHANGED_TOKEN =
      "a token-exchange actor exchanging an exchanged token";

  /** A person's (or service's) JWT exchanged: the token and its life are read. */
  static final GoldenInteraction EXCHANGE_PERSON =
      GoldenInteraction.of(PLATFORM_CALLER, EXCHANGING_A_PERSONS_TOKEN, "issueToken")
          .header("Authorization", "{authorization}")
          .consumes("access_token", "expires_in");

  /** A commissioned {@code qits_tok_} exchanged the same way. */
  static final GoldenInteraction EXCHANGE_COMMISSIONED =
      GoldenInteraction.of(PLATFORM_CALLER, EXCHANGING_A_COMMISSIONED_TOKEN, "issueToken")
          .header("Authorization", "{authorization}")
          .consumes("access_token", "expires_in");

  /** A client idp does not list as an actor: 400, the status is the whole verdict. */
  static final GoldenInteraction EXCHANGE_NOT_ACTOR =
      GoldenInteraction.of(PLATFORM_CALLER, NO_EXCHANGE_ACTOR, "issueToken")
          .header("Authorization", "{authorization}");

  /** A subject that is itself exchanged: 400, exchanges do not chain. */
  static final GoldenInteraction EXCHANGE_CHAINED =
      GoldenInteraction.of(PLATFORM_CALLER, EXCHANGING_AN_EXCHANGED_TOKEN, "issueToken")
          .header("Authorization", "{authorization}");

  /** The rows whose request body carries the state's fresh {@code subjectToken}. */
  static final Set<String> EXCHANGE_STATES =
      Set.of(
          EXCHANGING_A_PERSONS_TOKEN,
          EXCHANGING_A_COMMISSIONED_TOKEN,
          NO_EXCHANGE_ACTOR,
          EXCHANGING_AN_EXCHANGED_TOKEN);

  static final ConsumerPact PACT =
      ConsumerPact.of(
          CONSUMER,
          IDP,
          MINT,
          DISCOVERY,
          JWKS,
          INTROSPECT,
          INTROSPECT_DELETED,
          EXCHANGE_PERSON,
          EXCHANGE_COMMISSIONED,
          EXCHANGE_NOT_ACTOR,
          EXCHANGE_CHAINED);

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

  /**
   * The library's pact, with {@code $.subject_token} named by provider state on every exchange
   * row's form body — see the class comment.
   */
  static V4Pact pactWithStateTokens() {
    V4Pact pact = PACT.pact();
    for (Interaction interaction : pact.getInteractions()) {
      boolean exchange =
          interaction.getProviderStates().stream()
              .anyMatch(state -> EXCHANGE_STATES.contains(state.getName()));
      if (exchange) {
        interaction
            .asSynchronousRequestResponse()
            .getRequest()
            .getGenerators()
            .addGenerator(
                Category.BODY,
                "$.subject_token",
                new ProviderStateGenerator("${subjectToken}", DataType.STRING));
      }
    }
    return pact;
  }

  /**
   * {@code ConsumerPact.compareOrWritePactFile}, on {@link #pactWithStateTokens}: the same file, the
   * same normalisation, the same {@code -Dgolden.update=true}, and the raw copy under {@code
   * target/pacts}.
   */
  @Test
  void theCommittedPactIsWhatTheRowsWrite() throws Exception {
    assertTrue(PACT.unrecorded().isEmpty(), "every row is recorded: " + PACT.unrecorded());
    StringWriter written = new StringWriter();
    try (PrintWriter out = new PrintWriter(written)) {
      DefaultPactWriter.INSTANCE.writePact(pactWithStateTokens(), out, PactSpecVersion.V4);
    }
    Path raw = Path.of("target", "pacts", PACT.file());
    Files.createDirectories(raw.getParent());
    Files.writeString(raw, written.toString());
    GoldenFiles.compareOrWrite(
        ConsumerPact.pactsDirectory().resolve(PACT.file()),
        ConsumerPact.normalise(written.toString()));
  }

  @Test
  void theExchangeRowsSendTheStatesFreshSubjectToken() {
    V4Pact pact = pactWithStateTokens();
    int exchanges = 0;
    for (Interaction interaction : pact.getInteractions()) {
      if (interaction.getProviderStates().stream()
          .noneMatch(state -> EXCHANGE_STATES.contains(state.getName()))) {
        continue;
      }
      exchanges++;
      var request =
          interaction
              .asSynchronousRequestResponse()
              .getRequest()
              .generatedRequest(
                  // What a provider verification hands the generators: the state's parameters.
                  new java.util.HashMap<>(
                      Map.of(
                          "providerState",
                          Map.of("subjectToken", "fresh-subject", "authorization", "Basic fresh"))),
                  GeneratorTestMode.Provider);
      String body = request.getBody().valueAsString();
      assertTrue(body.contains("subject_token=fresh-subject"), body);
      assertTrue(body.contains("grant_type=urn"), body);
      assertEquals(List.of("Basic fresh"), request.getHeaders().get("Authorization"));
    }
    assertEquals(4, exchanges);
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
