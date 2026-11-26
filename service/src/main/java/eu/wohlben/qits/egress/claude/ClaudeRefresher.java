package eu.wohlben.qits.egress.claude;

import eu.wohlben.qits.egress.store.ClaudeCredentialStore;
import eu.wohlben.qits.egress.store.ClaudeCredentialStore.Refreshed;
import java.time.Clock;
import java.time.Duration;
import org.jboss.logging.Logger;

/**
 * <b>One replica's refresh of the held Claude login</b>: when less than {@code
 * qits.egress.claude.refresh-margin} (60 m) is left, the {@link ClaudeTokenEndpoint} is called
 * inside {@link ClaudeCredentialStore#refresh}'s transaction, which holds {@code SELECT … FOR
 * UPDATE} on the row — so of two replicas asking at once, one calls and the other waits, then finds
 * the row no longer due and calls nothing. The refresh token rotates on every call, which is why two
 * calls would be one too many: the second would spend the token the first just retired.
 *
 * <p>A failure is one WARN naming the fixed reason (never a body, never a token) and {@code
 * last_refresh_error}; the next check tries again. A plain class, so a suite can build two
 * replicas over the one database.
 */
public final class ClaudeRefresher {

  private static final Logger LOG = Logger.getLogger(ClaudeRefresher.class);

  private final ClaudeCredentialStore store;

  private final ClaudeTokenEndpoint endpoint;

  private final Duration margin;

  private final Clock clock;

  public ClaudeRefresher(
      ClaudeCredentialStore store, ClaudeTokenEndpoint endpoint, Duration margin, Clock clock) {
    this.store = store;
    this.endpoint = endpoint;
    this.margin = margin;
    this.clock = clock;
  }

  /** Refresh when due. Blocking: a database transaction around an outbound call. */
  public Refreshed refreshIfDue() {
    var now = clock.instant();
    var outcome = store.refresh(margin, now, held -> endpoint.refresh(held.refreshToken(), now));
    switch (outcome) {
      case ROTATED -> LOG.info("the claude credential is refreshed");
      case FAILED ->
          store
              .held()
              .ifPresent(
                  held ->
                      LOG.warnf(
                          "the claude credential could not be refreshed, retrying at the next"
                              + " check: %s (expires %s)",
                          held.lastRefreshError(), held.expiresAt()));
      default -> {}
    }
    return outcome;
  }
}
