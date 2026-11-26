package eu.wohlben.qits.egress.api;

import java.time.Instant;
import java.util.List;

/**
 * Everything the Claude credential door binds and answers (qits-2664). The {@code PUT} body is the
 * {@code claudeAiOauth} object of Claude Code's {@code .credentials.json}, as the runner reads it;
 * the {@code GET} answer is the held login's status and NEVER a token.
 */
public final class ClaudeCredentialWire {

  private ClaudeCredentialWire() {}

  /**
   * {@code claudeAiOauth}, as Claude Code writes it.
   *
   * @param expiresAt epoch milliseconds
   * @param refreshTokenExpiresAt epoch milliseconds, or null
   */
  public record ClaudeAiOauth(
      String accessToken,
      String refreshToken,
      Long expiresAt,
      Long refreshTokenExpiresAt,
      List<String> scopes,
      String subscriptionType,
      String rateLimitTier) {

    /** Never the tokens. */
    @Override
    public String toString() {
      return "ClaudeAiOauth[subscriptionType=" + subscriptionType + "]";
    }
  }

  /**
   * The held login's status: {@code held} false and every other field null when none is held.
   *
   * @param lastRefreshError why the last refresh failed, null after a success or a new login
   */
  public record ClaudeCredentialStatus(
      boolean held,
      Instant expiresAt,
      Instant refreshExpiresAt,
      List<String> scopes,
      String subscriptionType,
      String rateLimitTier,
      String source,
      Instant updatedAt,
      Instant lastRefreshAt,
      String lastRefreshError) {}

  /** {@code adopt} found a login held already. */
  public record Held(boolean held) {}

  /** A refusal's fixed text. */
  public record ErrorBody(String error) {}
}
