package eu.wohlben.qits.egress.claude;

import eu.wohlben.qits.egress.store.ClaudeCredentialStore;
import io.quarkus.runtime.ShutdownEvent;
import io.quarkus.runtime.StartupEvent;
import io.vertx.core.Vertx;
import io.vertx.core.http.HttpClient;
import io.vertx.core.http.HttpClientOptions;
import jakarta.annotation.PostConstruct;
import jakarta.enterprise.event.Observes;
import jakarta.inject.Inject;
import jakarta.inject.Singleton;
import java.time.Clock;
import java.time.Duration;
import java.util.concurrent.atomic.AtomicBoolean;
import org.eclipse.microprofile.config.inject.ConfigProperty;
import org.jboss.logging.Logger;

/**
 * <b>This replica's copy of the held Claude login</b> (epic qits-2525, qits-2664), what the proxy
 * swaps for the placeholder: the row is read at boot, every {@code qits.egress.claude.reread} (30 s),
 * at once after a store at the door and after this replica's own refresh. The refresh itself
 * ({@link ClaudeRefresher}) is checked every {@code qits.egress.claude.refresh-check} (5 m); only
 * the replica that takes the row lock calls.
 *
 * <p>Nothing here gates readiness: with no login held, a placeholder request answers 503.
 */
@Singleton
public class ClaudeCredentials {

  private static final Logger LOG = Logger.getLogger(ClaudeCredentials.class);

  /** What a container holds instead of the login, as token and as refresh token. */
  public static final String PLACEHOLDER = "qits-egress-placeholder";

  /**
   * What the proxy needs of the held login: the two tokens (swapped in, and scrubbed back out) and
   * the scopes (the synthetic refresh answer names them).
   *
   * @param scopes space separated
   */
  public record Held(String accessToken, String refreshToken, String scopes) {

    /** Never the tokens. */
    @Override
    public String toString() {
      return "Held[scopes=" + scopes + "]";
    }
  }

  @Inject Vertx vertx;

  @Inject ClaudeCredentialStore store;

  @ConfigProperty(
      name = "qits.egress.claude.token-url",
      defaultValue = "https://platform.claude.com/v1/oauth/token")
  String tokenUrl;

  @ConfigProperty(
      name = "qits.egress.claude.client-id",
      defaultValue = "9d1c250a-e61b-44d9-88ed-5944d1962f5e")
  String clientId;

  @ConfigProperty(name = "qits.egress.claude.refresh-check", defaultValue = "5m")
  Duration refreshCheck;

  @ConfigProperty(name = "qits.egress.claude.refresh-margin", defaultValue = "60m")
  Duration refreshMargin;

  @ConfigProperty(name = "qits.egress.claude.reread", defaultValue = "30s")
  Duration reread;

  @ConfigProperty(name = "qits.egress.claude.timeout", defaultValue = "30s")
  Duration timeout;

  private volatile Held current;

  private HttpClient client;

  private ClaudeRefresher refresher;

  private final AtomicBoolean rereading = new AtomicBoolean();

  private final AtomicBoolean refreshing = new AtomicBoolean();

  private long rereadTimer = -1;

  private long refreshTimer = -1;

  @PostConstruct
  void build() {
    // A small client of its own, never the proxy's; TLS by the JVM trust store (quarkus.ssl.native).
    client = vertx.createHttpClient(new HttpClientOptions().setKeepAlive(false).setVerifyHost(true));
    refresher =
        new ClaudeRefresher(
            store,
            new ClaudeTokenEndpoint(client, tokenUrl, clientId, timeout.toMillis()),
            refreshMargin,
            Clock.systemUTC());
  }

  /** The login this replica holds, or null. Never blocks. */
  public Held current() {
    return current;
  }

  /** Read the row again. Blocking. */
  public void reload() {
    current =
        store
            .held()
            .map(held -> new Held(held.accessToken(), held.refreshToken(), held.scopes()))
            .orElse(null);
  }

  /** Refresh when due, then read the row again. Blocking. */
  public void refreshIfDue() {
    refresher.refreshIfDue();
    reload();
  }

  void start(@Observes StartupEvent ignored) {
    try {
      reload();
    } catch (RuntimeException e) {
      LOG.warnf("could not read the claude credential at boot, retrying every %s: %s", reread, e);
    }
    rereadTimer = vertx.setPeriodic(reread.toMillis(), id -> blocking("re-read", rereading, this::reload));
    refreshTimer =
        vertx.setPeriodic(refreshCheck.toMillis(), id -> blocking("refresh", refreshing, this::refreshIfDue));
  }

  /** One blocking pass off the event loop; a database that hangs stacks no second one. */
  private void blocking(String what, AtomicBoolean busy, Runnable pass) {
    if (!busy.compareAndSet(false, true)) {
      return;
    }
    vertx
        .executeBlocking(
            () -> {
              pass.run();
              return null;
            },
            false)
        .onComplete(done -> busy.set(false))
        .onFailure(e -> LOG.warnf("could not %s the claude credential: %s", what, e.toString()));
  }

  void stop(@Observes ShutdownEvent ignored) {
    if (rereadTimer >= 0) {
      vertx.cancelTimer(rereadTimer);
    }
    if (refreshTimer >= 0) {
      vertx.cancelTimer(refreshTimer);
    }
    if (client != null) {
      client.close();
    }
  }
}
