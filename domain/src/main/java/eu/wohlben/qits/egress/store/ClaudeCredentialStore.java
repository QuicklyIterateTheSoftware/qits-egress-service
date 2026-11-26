package eu.wohlben.qits.egress.store;

import eu.wohlben.qits.db.DbRetry;
import io.agroal.api.AgroalDataSource;
import io.quarkus.agroal.DataSource;
import jakarta.enterprise.context.ApplicationScoped;
import jakarta.inject.Inject;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Types;
import java.time.Duration;
import java.time.Instant;
import java.time.OffsetDateTime;
import java.time.ZoneOffset;
import java.util.Optional;

/**
 * <b>The one Claude login this service holds</b> (epic qits-2525, qits-2664): the row {@code
 * egress_claude_credential.id = 1}, stored by the runner's {@code PUT /egress/api/claude-credential}
 * and refreshed by whichever replica takes the row lock first.
 *
 * <p><b>Plain JDBC, not an entity</b>, as {@link GrantTableStore}: one row, read whole, mapped by no
 * API field by field (the status door serves a projection without the tokens).
 *
 * <p><b>The tokens are plaintext here and nowhere else.</b> {@link Credential#toString()} names
 * neither; no method logs one, and every failure message is a fixed text.
 *
 * <p><b>One replica refreshes</b> ({@link #refresh}): the check and the upstream call run inside one
 * transaction holding {@code SELECT … FOR UPDATE} on the row, so a second replica asking at the same
 * moment waits for the first to commit and then finds the row no longer due. The refresh is NOT
 * wrapped in {@link DbRetry}: a retried transaction would send the rotated refresh token's
 * predecessor a second time.
 */
@ApplicationScoped
public class ClaudeCredentialStore {

  /** The key of the one row. */
  static final short ID = 1;

  /**
   * The held login.
   *
   * @param scopes space separated
   */
  public record Credential(
      String accessToken,
      String refreshToken,
      Instant expiresAt,
      Instant refreshExpiresAt,
      String scopes,
      String subscriptionType,
      String rateLimitTier,
      String source,
      Instant updatedAt,
      Instant lastRefreshAt,
      String lastRefreshError) {

    /** Never the tokens. */
    @Override
    public String toString() {
      return "Credential[expiresAt=" + expiresAt + ", source=" + source + "]";
    }
  }

  /** What arrives at the door: a login, without the bookkeeping. */
  public record Login(
      String accessToken,
      String refreshToken,
      Instant expiresAt,
      Instant refreshExpiresAt,
      String scopes,
      String subscriptionType,
      String rateLimitTier,
      String source) {

    /** Never the tokens. */
    @Override
    public String toString() {
      return "Login[expiresAt=" + expiresAt + ", source=" + source + "]";
    }
  }

  /** What a refresh call answered: the rotated pair, or why it failed. */
  public record Rotation(
      String accessToken, String refreshToken, Instant expiresAt, String scopes, String error) {

    public static Rotation failed(String error) {
      return new Rotation(null, null, null, null, error);
    }

    public boolean succeeded() {
      return error == null;
    }

    /** Never the tokens. */
    @Override
    public String toString() {
      return succeeded() ? "Rotation[expiresAt=" + expiresAt + "]" : "Rotation[error=" + error + "]";
    }
  }

  /** The call a due refresh makes, while the row is locked. */
  @FunctionalInterface
  public interface RefreshCall {
    Rotation call(Credential held);
  }

  /** What {@link #refresh} did. */
  public enum Refreshed {
    /** Nothing is held. */
    NOT_HELD,
    /** More than the margin is left: nothing called. */
    NOT_DUE,
    /** Called, and the rotated pair is stored. */
    ROTATED,
    /** Called, and it failed: {@code last_refresh_error} is set. */
    FAILED
  }

  @Inject
  @DataSource("egress")
  AgroalDataSource egress;

  private static final String COLUMNS =
      "access_token, refresh_token, expires_at, refresh_expires_at, scopes, subscription_type,"
          + " rate_limit_tier, source, updated_at, last_refresh_at, last_refresh_error";

  /** The held login, or empty. */
  public Optional<Credential> held() {
    return DbRetry.call(
        "read the claude credential",
        () -> {
          try (Connection db = egress.getConnection();
              PreparedStatement read =
                  db.prepareStatement(
                      "select " + COLUMNS + " from egress.egress_claude_credential where id = ?")) {
            read.setShort(1, ID);
            try (ResultSet row = read.executeQuery()) {
              return row.next() ? Optional.of(credential(row)) : Optional.<Credential>empty();
            }
          } catch (SQLException e) {
            throw new IllegalStateException("reading the claude credential failed", e);
          }
        });
  }

  /**
   * Store {@code login} only when nothing is held.
   *
   * @return whether it was stored
   */
  public boolean adopt(Login login) {
    return DbRetry.call(
        "adopt the claude credential",
        () -> write(login, "on conflict (id) do nothing") > 0);
  }

  /** Store {@code login} whatever is held: a fresh sign-in. */
  public void replace(Login login) {
    DbRetry.run(
        "replace the claude credential",
        () ->
            write(
                login,
                "on conflict (id) do update set access_token = excluded.access_token,"
                    + " refresh_token = excluded.refresh_token, expires_at = excluded.expires_at,"
                    + " refresh_expires_at = excluded.refresh_expires_at, scopes = excluded.scopes,"
                    + " subscription_type = excluded.subscription_type,"
                    + " rate_limit_tier = excluded.rate_limit_tier, source = excluded.source,"
                    + " updated_at = excluded.updated_at, last_refresh_at = null,"
                    + " last_refresh_error = null"));
  }

  /**
   * Refresh the held login when less than {@code margin} is left, holding the row lock throughout:
   * {@code call} runs inside the transaction, so no other replica calls at the same time.
   */
  public Refreshed refresh(Duration margin, Instant now, RefreshCall call) {
    try (Connection db = egress.getConnection()) {
      boolean autoCommit = db.getAutoCommit();
      db.setAutoCommit(false);
      try {
        Refreshed refreshed = refreshLocked(db, margin, now, call);
        db.commit();
        return refreshed;
      } catch (SQLException | RuntimeException e) {
        db.rollback();
        throw e;
      } finally {
        db.setAutoCommit(autoCommit);
      }
    } catch (SQLException e) {
      throw new IllegalStateException("refreshing the claude credential failed", e);
    }
  }

  private Refreshed refreshLocked(Connection db, Duration margin, Instant now, RefreshCall call)
      throws SQLException {
    Credential held;
    try (PreparedStatement lock =
        db.prepareStatement(
            "select " + COLUMNS + " from egress.egress_claude_credential where id = ? for update")) {
      lock.setShort(1, ID);
      try (ResultSet row = lock.executeQuery()) {
        if (!row.next()) {
          return Refreshed.NOT_HELD;
        }
        held = credential(row);
      }
    }
    if (Duration.between(now, held.expiresAt()).compareTo(margin) >= 0) {
      return Refreshed.NOT_DUE;
    }
    Rotation rotation = call.call(held);
    if (rotation == null || !rotation.succeeded()) {
      try (PreparedStatement failed =
          db.prepareStatement(
              "update egress.egress_claude_credential set last_refresh_error = ? where id = ?")) {
        failed.setString(1, rotation == null ? "no answer" : rotation.error());
        failed.setShort(2, ID);
        failed.executeUpdate();
      }
      return Refreshed.FAILED;
    }
    try (PreparedStatement rotated =
        db.prepareStatement(
            "update egress.egress_claude_credential set access_token = ?, refresh_token = ?,"
                + " expires_at = ?, scopes = coalesce(?, scopes), updated_at = ?,"
                + " last_refresh_at = ?, last_refresh_error = null where id = ?")) {
      rotated.setString(1, rotation.accessToken());
      rotated.setString(
          2, rotation.refreshToken() == null ? held.refreshToken() : rotation.refreshToken());
      rotated.setObject(3, at(rotation.expiresAt()));
      rotated.setString(4, rotation.scopes());
      rotated.setObject(5, at(now));
      rotated.setObject(6, at(now));
      rotated.setShort(7, ID);
      rotated.executeUpdate();
    }
    return Refreshed.ROTATED;
  }

  /** Forget the held login. For the suites' provider states; no door calls it. */
  public void clear() {
    DbRetry.run(
        "clear the claude credential",
        () -> {
          try (Connection db = egress.getConnection();
              PreparedStatement delete =
                  db.prepareStatement("delete from egress.egress_claude_credential where id = ?")) {
            delete.setShort(1, ID);
            delete.executeUpdate();
          } catch (SQLException e) {
            throw new IllegalStateException("clearing the claude credential failed", e);
          }
        });
  }

  private int write(Login login, String conflict) {
    try (Connection db = egress.getConnection();
        PreparedStatement insert =
            db.prepareStatement(
                "insert into egress.egress_claude_credential (id, " + COLUMNS + ")"
                    + " values (?, ?, ?, ?, ?, ?, ?, ?, ?, now(), null, null) "
                    + conflict)) {
      insert.setShort(1, ID);
      insert.setString(2, login.accessToken());
      insert.setString(3, login.refreshToken());
      insert.setObject(4, at(login.expiresAt()));
      insert.setObject(5, at(login.refreshExpiresAt()), Types.TIMESTAMP_WITH_TIMEZONE);
      insert.setString(6, login.scopes() == null ? "" : login.scopes());
      insert.setString(7, login.subscriptionType());
      insert.setString(8, login.rateLimitTier());
      insert.setString(9, login.source());
      return insert.executeUpdate();
    } catch (SQLException e) {
      throw new IllegalStateException("storing the claude credential failed", e);
    }
  }

  private static Credential credential(ResultSet row) throws SQLException {
    return new Credential(
        row.getString(1),
        row.getString(2),
        instant(row, 3),
        instant(row, 4),
        row.getString(5),
        row.getString(6),
        row.getString(7),
        row.getString(8),
        instant(row, 9),
        instant(row, 10),
        row.getString(11));
  }

  private static OffsetDateTime at(Instant instant) {
    return instant == null ? null : OffsetDateTime.ofInstant(instant, ZoneOffset.UTC);
  }

  private static Instant instant(ResultSet row, int column) throws SQLException {
    OffsetDateTime value = row.getObject(column, OffsetDateTime.class);
    return value == null ? null : value.toInstant();
  }
}
