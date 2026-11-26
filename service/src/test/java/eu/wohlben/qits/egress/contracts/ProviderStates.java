package eu.wohlben.qits.egress.contracts;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import eu.wohlben.qits.egress.api.ClaudeCredentialWire;
import eu.wohlben.qits.egress.api.GrantTableWire;
import eu.wohlben.qits.egress.claude.ClaudeCredentials;
import eu.wohlben.qits.egress.grants.GrantIndex;
import eu.wohlben.qits.egress.store.ClaudeCredentialStore;
import eu.wohlben.qits.egress.store.GrantTableStore;
import eu.wohlben.qits.egress.support.ContractCallers;
import jakarta.enterprise.context.ApplicationScoped;
import jakarta.inject.Inject;
import java.time.Instant;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import java.util.TreeMap;
import java.util.function.Supplier;

/**
 * <b>qits-egress' provider states</b>: each one clears the store, stages what one consumer
 * situation needs and hands back its parameters. Two callers: {@link GoldenMasterRecordingTest}
 * runs a state before each operation that names it, and {@link ConsumerPactVerificationTest}'s
 * {@code @State} methods delegate here.
 *
 * <p>The consumer is qits-deployments' push client (late work of epic qits-2523): it pushes the
 * table and reads the held version back, as its own service client. So every state also grants
 * {@value #PUBLISHER_BEARER} as that client — {@code sub} {@code dev-qits-deployments}, {@code
 * groups} holding {@code clients/dev-qits-deployments} and {@code qits:system} — and hands it as
 * {@code authorization}, the bearer the consumer's pact sends.
 *
 * <p>{@value #A_GRANT_TABLE_IS_HELD} holds {@link #TABLE}: one route, qits-edge's {@code hetzner},
 * the same table qits-deployments' own golden master {@code an-egress-grant-table-with-one-route}
 * serves, at the same version. Every state starts from an empty store, so applying it twice is the
 * same state.
 *
 * <p>The Claude credential door's consumer is the runner (qits-system-runner-daemon, qits-2664): its
 * states, {@value #A_CLAUDE_CREDENTIAL_IS_HELD} and {@value #NO_CLAUDE_CREDENTIAL_IS_HELD}, grant
 * {@value #RUNNER_BEARER} as {@code qits:target-runner} and hand it as {@code authorization}.
 */
@ApplicationScoped
public class ProviderStates {

  public static final String A_GRANT_TABLE_IS_HELD = "a grant table is held";

  public static final String NO_GRANT_TABLE_IS_HELD = "no grant table is held";

  public static final String A_CLAUDE_CREDENTIAL_IS_HELD = "a claude credential is held";

  public static final String NO_CLAUDE_CREDENTIAL_IS_HELD = "no claude credential is held";

  /** The runner's client in the suite: the Claude credential door's one writer (qits-2664). */
  public static final String RUNNER = "contract-target-runner";

  /** The bearer the runner presents. */
  public static final String RUNNER_BEARER = "Bearer contract-qits-target-runner";

  /** The login the held state holds; the door never answers either token. */
  public static final ClaudeCredentialStore.Login HELD_LOGIN =
      new ClaudeCredentialStore.Login(
          "contract-held-access-token",
          "contract-held-refresh-token",
          Instant.parse("2026-12-01T12:00:00Z"),
          Instant.parse("2027-12-01T12:00:00Z"),
          "user:inference user:profile user:sessions:claude_code",
          "max",
          "default_claude_max_20x",
          "hand-over " + RUNNER);

  /** The {@code claudeAiOauth} both states' {@code PUT ?mode=adopt} sends. */
  public static final ClaudeCredentialWire.ClaudeAiOauth ADOPTED_LOGIN =
      new ClaudeCredentialWire.ClaudeAiOauth(
          "contract-handed-over-access-token",
          "contract-handed-over-refresh-token",
          1796126400000L,
          1827662400000L,
          List.of("user:inference", "user:profile", "user:sessions:claude_code"),
          "max",
          "default_claude_max_20x");

  /** The deployer's client id in the suite's environment. */
  public static final String PUBLISHER = "dev-qits-deployments";

  /** The bearer the publisher presents. */
  public static final String PUBLISHER_BEARER = "Bearer contract-qits-deployments";

  /** The table the held state holds, and the one both states' {@code PUT} sends. */
  public static final GrantTableWire.GrantTable TABLE =
      new GrantTableWire.GrantTable(
          1764061200000L,
          List.of(
              new GrantTableWire.Route(
                  "qits-edge",
                  "dev",
                  "2026.1201.101010",
                  "hetzner",
                  "https://api.hetzner.cloud",
                  "HETZNER_DNS",
                  "bearer",
                  List.of("DELETE", "GET", "POST", "PUT"))),
          List.of());

  /** What a state hands back: its parameters, keys sorted, and no unique tokens. */
  public record Setup(Map<String, String> params) {
    public List<String> uniqueTokens() {
      return List.of();
    }
  }

  private final Map<String, Supplier<Setup>> states = new LinkedHashMap<>();

  @Inject GrantTableStore store;

  @Inject GrantIndex index;

  @Inject ClaudeCredentialStore claudeStore;

  @Inject ClaudeCredentials claudeCredentials;

  @Inject ObjectMapper json;

  public ProviderStates() {
    states.put(A_GRANT_TABLE_IS_HELD, this::aGrantTableIsHeld);
    states.put(NO_GRANT_TABLE_IS_HELD, this::noGrantTableIsHeld);
    states.put(A_CLAUDE_CREDENTIAL_IS_HELD, this::aClaudeCredentialIsHeld);
    states.put(NO_CLAUDE_CREDENTIAL_IS_HELD, this::noClaudeCredentialIsHeld);
  }

  public Set<String> names() {
    return Collections.unmodifiableSet(states.keySet());
  }

  public Setup setUp(String state) {
    Supplier<Setup> setup = states.get(state);
    if (setup == null) {
      throw new IllegalArgumentException(
          "No provider state '" + state + "' — this provider answers for " + states.keySet());
    }
    return setup.get();
  }

  public Map<String, String> params(String state) {
    return setUp(state).params();
  }

  /** The state's slug: lower-cased, every run of non-alphanumerics replaced by {@code -}. */
  public static String slug(String state) {
    return state.toLowerCase(Locale.ROOT).replaceAll("[^a-z0-9]+", "-");
  }

  /** The {@link #TABLE} as the JSON the {@code PUT} sends. */
  public static String tableJson(ObjectMapper json) {
    try {
      return json.writeValueAsString(TABLE);
    } catch (JsonProcessingException e) {
      throw new IllegalStateException(e);
    }
  }

  /** Grant {@link #PUBLISHER_BEARER} as the deployer's own client. */
  public static void grantPublisher() {
    ContractCallers.bearer(
        PUBLISHER_BEARER,
        PUBLISHER,
        Set.of("clients/" + PUBLISHER, "qits:system"),
        Set.of("clients/" + PUBLISHER, "qits:system"));
  }

  /** The {@link #ADOPTED_LOGIN} as the JSON the {@code PUT} sends. */
  public static String adoptedLoginJson(ObjectMapper json) {
    try {
      return json.writeValueAsString(ADOPTED_LOGIN);
    } catch (JsonProcessingException e) {
      throw new IllegalStateException(e);
    }
  }

  /** Grant {@link #RUNNER_BEARER} as the runner's own client: {@code qits:target-runner}. */
  public static void grantRunner() {
    ContractCallers.bearer(
        RUNNER_BEARER, RUNNER, Set.of("clients/" + RUNNER), Set.of("qits:target-runner"));
  }

  // --- the states ------------------------------------------------------------------------------

  private Setup aGrantTableIsHeld() {
    store.clear();
    store.store(TABLE.version(), tableJson(json), "application:qits-deployments");
    index.refresh();
    return publisherParams();
  }

  private Setup noGrantTableIsHeld() {
    store.clear();
    index.refresh();
    return publisherParams();
  }

  private Setup aClaudeCredentialIsHeld() {
    claudeStore.clear();
    claudeStore.replace(HELD_LOGIN);
    claudeCredentials.reload();
    return runnerParams();
  }

  private Setup noClaudeCredentialIsHeld() {
    claudeStore.clear();
    claudeCredentials.reload();
    return runnerParams();
  }

  private static Setup runnerParams() {
    grantRunner();
    return new Setup(Map.of("authorization", RUNNER_BEARER));
  }

  private static Setup publisherParams() {
    grantPublisher();
    Map<String, String> params = new TreeMap<>();
    params.put("authorization", PUBLISHER_BEARER);
    params.put("version", String.valueOf(TABLE.version()));
    return new Setup(Collections.unmodifiableMap(params));
  }
}
