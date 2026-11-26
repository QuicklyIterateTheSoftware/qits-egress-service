package eu.wohlben.qits.egress.contracts;

import static org.junit.jupiter.api.Assertions.fail;

import au.com.dius.pact.core.model.Interaction;
import au.com.dius.pact.core.model.Pact;
import au.com.dius.pact.core.model.ProviderState;
import au.com.dius.pact.provider.junit5.HttpTestTarget;
import au.com.dius.pact.provider.junit5.PactVerificationContext;
import au.com.dius.pact.provider.junit5.PactVerificationInvocationContextProvider;
import au.com.dius.pact.provider.junitsupport.IgnoreNoPactsToVerify;
import au.com.dius.pact.provider.junitsupport.Provider;
import au.com.dius.pact.provider.junitsupport.State;
import au.com.dius.pact.provider.junitsupport.loader.PactSource;
import io.quarkus.test.common.http.TestHTTPResource;
import io.quarkus.test.junit.QuarkusTest;
import jakarta.inject.Inject;
import java.net.URL;
import java.util.List;
import java.util.Map;
import org.apache.hc.core5.http.ClassicHttpRequest;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.TestTemplate;
import org.junit.jupiter.api.extension.ExtendWith;

/**
 * <b>Verifies every consumer's pact against the running qits-egress</b>, the way
 * qits-agents-service does.
 *
 * <p>Each consumer publishes its pact as a jar holding {@code
 * pacts/<consumer>_qits-egress-service.json}; this repository pins the jar as a test dependency and
 * {@link ClasspathPactLoader} finds it. <b>No consumer pins one yet</b> (qits-deployments' push
 * client will, late in epic qits-2523), so this class carries {@link IgnoreNoPactsToVerify} and
 * {@link ClasspathPactLoader#REQUIRED} is false; drop the one and flip the other when the first jar
 * is pinned.
 *
 * <p>An interaction that carries its own {@code Authorization} — the state's {@code authorization},
 * qits-deployments' own client — is verified as that caller; one that carries none runs as that
 * same publisher, the only caller the push admits. Every {@code @State} method delegates to {@link
 * ProviderStates}; {@link #target} fails an unknown state, and an interaction without {@code
 * comments.references.qits-call} or {@code qits-trigger}.
 */
@QuarkusTest
@Provider(ConsumerPactVerificationTest.PROVIDER)
@PactSource(ClasspathPactLoader.class)
@IgnoreNoPactsToVerify
class ConsumerPactVerificationTest {

  /** The provider's name in a pact: the repository name, not the application name. */
  static final String PROVIDER = "qits-egress-service";

  static {
    // pact-jvm reports usage metrics over the network unless told not to; a test never should.
    System.setProperty("pact_do_not_track", "true");
  }

  @Inject ProviderStates states;

  @TestHTTPResource("/")
  URL base;

  @BeforeEach
  void target(PactVerificationContext context, Pact pact, Interaction interaction) {
    if (context == null) {
      return; // No pact: nothing to target.
    }
    String consumer = pact.getConsumer().getName();
    for (ProviderState state : interaction.getProviderStates()) {
      if (!states.names().contains(state.getName())) {
        fail(
            "Consumer '"
                + consumer
                + "' needs the provider state '"
                + state.getName()
                + "' (interaction '"
                + interaction.getDescription()
                + "'), which qits-egress does not answer for — it answers for "
                + states.names());
      }
    }
    var references = interaction.getComments().get("references");
    for (String key : List.of("qits-call", "qits-trigger")) {
      if (references == null || !references.isObject() || !references.asObject().has(key)) {
        fail(
            "Consumer '"
                + consumer
                + "' interaction '"
                + interaction.getDescription()
                + "' carries no comments.references."
                + key);
      }
    }
    context.setTarget(new HttpTestTarget(base.getHost(), base.getPort()));
  }

  @TestTemplate
  @ExtendWith(PactVerificationInvocationContextProvider.class)
  void consumerPactHolds(PactVerificationContext context, ClassicHttpRequest request) {
    if (context == null) {
      return;
    }
    if (request != null && !request.containsHeader("Authorization")) {
      ProviderStates.grantPublisher();
      request.setHeader("Authorization", ProviderStates.PUBLISHER_BEARER);
    }
    context.verifyInteraction();
  }

  // --- the states: each one line into the registry -------------------------------------------

  @State(ProviderStates.A_GRANT_TABLE_IS_HELD)
  Map<String, String> aGrantTableIsHeld() {
    return states.params(ProviderStates.A_GRANT_TABLE_IS_HELD);
  }

  @State(ProviderStates.NO_GRANT_TABLE_IS_HELD)
  Map<String, String> noGrantTableIsHeld() {
    return states.params(ProviderStates.NO_GRANT_TABLE_IS_HELD);
  }

  @State(ProviderStates.A_CLAUDE_CREDENTIAL_IS_HELD)
  Map<String, String> aClaudeCredentialIsHeld() {
    return states.params(ProviderStates.A_CLAUDE_CREDENTIAL_IS_HELD);
  }

  @State(ProviderStates.NO_CLAUDE_CREDENTIAL_IS_HELD)
  Map<String, String> noClaudeCredentialIsHeld() {
    return states.params(ProviderStates.NO_CLAUDE_CREDENTIAL_IS_HELD);
  }
}
