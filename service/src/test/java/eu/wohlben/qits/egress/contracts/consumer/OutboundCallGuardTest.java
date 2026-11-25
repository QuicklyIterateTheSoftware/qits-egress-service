package eu.wohlben.qits.egress.contracts.consumer;

import static com.tngtech.archunit.lang.syntax.ArchRuleDefinition.noClasses;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.tngtech.archunit.core.domain.JavaClasses;
import com.tngtech.archunit.core.importer.ClassFileImporter;
import com.tngtech.archunit.core.importer.ImportOption;
import eu.wohlben.qits.pact.consumer.GoldenInteraction;
import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Files;
import java.util.List;
import java.util.Map;
import java.util.Properties;
import java.util.Set;
import java.util.TreeSet;
import java.util.stream.Collectors;
import org.junit.jupiter.api.Test;

/**
 * <b>Every call this service makes to a qits service has a pact row</b> (qits-1149), the calls read
 * off the code rather than listed by hand:
 *
 * <ul>
 *   <li>only the classes in {@link #DIALLERS} reach a way to dial out — {@code
 *       java.net.http.HttpClient}, {@code HttpURLConnection}, a Vert.x {@code WebClient} or {@code
 *       HttpClient}, or {@code quarkus-oidc-client}'s {@code OidcClient} — and each one's calls are
 *       named there with the rows that cover them;
 *   <li>the named client {@code qits} is the only client-credentials mint, and its mint is rowed;
 *       the tenant's discovery and JWKS reads are rowed.
 * </ul>
 *
 * <p>Not seen here, because a library makes them: the OTLP export. Not a qits service, so no pact:
 * the proxy's upstream calls, which go to the third parties the grant table names (a {@code
 * platform:} route's call to a platform service comes with qits-2623, and its row with it).
 *
 * <p>THIS SERVICE IS PUBLIC: it can reach public platform services only. qits-projects,
 * qits-deployments, qits-ci and every other {@code exposure: private} service are unreachable from
 * it, so no row here may name one.
 */
class OutboundCallGuardTest {

  private static final Set<String> DIAL_OUT =
      Set.of(
          "java.net.http.HttpClient",
          "java.net.HttpURLConnection",
          "io.vertx.ext.web.client.WebClient",
          "io.vertx.core.http.HttpClient",
          "io.quarkus.oidc.client.OidcClient",
          "io.quarkus.oidc.client.OidcClients");

  /** Who may dial, and what each one's calls are. */
  static final Map<String, String> DIALLERS =
      Map.of(
          "eu.wohlben.qits.egress.identity.CallerIdentity",
          "builds the idp client IdpKeys and IdpIntrospection share",
          "eu.wohlben.qits.egress.identity.IdpKeys",
          "qits-idp getOpenIdConfiguration and getJwks (IdpPactTest DISCOVERY, JWKS)",
          "eu.wohlben.qits.egress.identity.IdpIntrospection",
          "qits-idp introspectToken (IdpPactTest INTROSPECT, INTROSPECT_DELETED)",
          "eu.wohlben.qits.egress.proxy.EgressProxy",
          "the proxied call to a granted route's third-party target: no qits service",
          "eu.wohlben.qits.egress.proxy.ProxyClients",
          "builds the proxy's upstream client");

  private static final JavaClasses PRODUCTION =
      new ClassFileImporter()
          .withImportOption(new ImportOption.DoNotIncludeTests())
          .importPackages("eu.wohlben.qits.egress");

  @Test
  void onlyTheNamedClassesDial() {
    String allowed =
        "("
            + DIALLERS.keySet().stream()
                .map(name -> name.replace(".", "\\."))
                .collect(Collectors.joining("|"))
            + ")(\\$.*)?";
    noClasses()
        .that()
        .haveNameNotMatching(allowed)
        .should()
        .dependOnClassesThat()
        .haveNameMatching(
            DIAL_OUT.stream().map(name -> name.replace(".", "\\.")).collect(Collectors.joining("|")))
        .because(
            "an outbound call to another qits service has a pact row against that provider's"
                + " golden masters (qits-1149): a new dialler joins DIALLERS with its rows")
        .allowEmptyShould(true)
        .check(PRODUCTION);
  }

  @Test
  void theProxysIdpCallsAreRowed() {
    Set<String> rowed =
        IdpPactTest.PACT.rows().stream().map(GoldenInteraction::operationId).collect(Collectors.toSet());
    for (String operation : List.of("getOpenIdConfiguration", "getJwks", "introspectToken")) {
      assertTrue(rowed.contains(operation), "the proxy listener's identity calls " + operation);
    }
  }

  @Test
  void theConfiguredOidcTenantsReadsArePacted() throws IOException {
    Properties properties = shipped();
    String server = properties.getProperty("quarkus.oidc.auth-server-url", "");
    assertTrue(server.contains("//idp.qits."), "the tenant reads qits-idp at its edge host: " + server);
    Set<String> rowed =
        IdpPactTest.PACT.rows().stream().map(GoldenInteraction::operationId).collect(Collectors.toSet());
    assertTrue(rowed.contains("getJwks"), "the tenant reads the JWKS: row getJwks");
    boolean discovery =
        Boolean.parseBoolean(properties.getProperty("quarkus.oidc.discovery-enabled", "true"));
    assertEquals(discovery, rowed.contains("getOpenIdConfiguration"), "the discovery row follows the tenant");
  }

  @Test
  void theQitsClientIsTheOnlyMintAndItIsRowed() throws IOException {
    Properties properties = shipped();
    Set<String> clientKeys =
        properties.stringPropertyNames().stream()
            .filter(name -> name.startsWith("quarkus.oidc-client."))
            .collect(Collectors.toCollection(TreeSet::new));
    assertFalse(clientKeys.isEmpty(), "the qits client is configured in application.properties");
    assertEquals(
        Set.of(),
        clientKeys.stream()
            .filter(name -> !name.startsWith("quarkus.oidc-client.qits."))
            .collect(Collectors.toSet()),
        "only the named client `qits` mints tokens here");
    assertEquals("client", properties.getProperty("quarkus.oidc-client.qits.grant.type"));
    assertTrue(
        IdpPactTest.PACT.rows().stream().anyMatch(row -> row.operationId().equals("issueToken")),
        "the qits client mints at qits-idp: row issueToken in IdpPactTest");
  }

  /** The shipped file, not the classpath's: a test resource of the same name shadows it there. */
  private static Properties shipped() throws IOException {
    Properties properties = new Properties();
    try (InputStream in =
        Files.newInputStream(java.nio.file.Path.of("src/main/resources/application.properties"))) {
      properties.load(in);
    }
    return properties;
  }
}
