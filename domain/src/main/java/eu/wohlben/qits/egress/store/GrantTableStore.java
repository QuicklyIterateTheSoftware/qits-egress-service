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
import java.time.Instant;
import java.time.OffsetDateTime;
import java.util.Optional;

/**
 * <b>The one grant table this service holds</b>: the row {@code egress_grant_table.id = 'egress'},
 * written by the {@code PUT} qits-deployments pushes and read by every replica.
 *
 * <p><b>Plain JDBC, not an entity.</b> The store is one row of three facts and a JSON body that is
 * only ever read whole; an entity would bring a persistence unit, a causation marker and an exposure
 * map for a row no API maps field by field. The body is the table as the deployer pushed it,
 * re-serialised by the door, so what is read back is what was admitted.
 *
 * <p><b>Versions only move up</b>, and the rule is one statement: the upsert writes only when the
 * incoming version is above the held one, so two replicas taking two pushes at once cannot store
 * the older one last. Every call is wrapped in {@link DbRetry}'s patience, which waits out a postgres
 * that is moving rather than failing a push or a replica's refresh on the first dropped connection;
 * the conditional upsert makes a retried write harmless.
 */
@ApplicationScoped
public class GrantTableStore {

  /** The key of the one row. */
  static final String ID = "egress";

  /** What the store holds: the version, the body as stored, when and from whom it came. */
  public record Held(long version, String body, Instant receivedAt, String receivedFrom) {}

  /** What a push did. */
  public enum Outcome {
    /** The incoming version was above the held one, or nothing was held: it is stored now. */
    STORED,
    /** The incoming version equals the held one: nothing changed, the push is idempotent. */
    UNCHANGED,
    /** The incoming version is below the held one: refused, the held table stays. */
    OLDER
  }

  /** A push's outcome and the version held after it. */
  public record Stored(Outcome outcome, long held) {}

  @Inject
  @DataSource("egress")
  AgroalDataSource egress;

  /** The held version, or empty when no table was ever pushed. The replicas' cheap poll. */
  public Optional<Long> version() {
    return DbRetry.call("read the grant table's version", this::readVersion);
  }

  /** The held table, or empty when no table was ever pushed. */
  public Optional<Held> held() {
    return DbRetry.call(
        "read the grant table",
        () -> {
          try (Connection db = egress.getConnection();
              PreparedStatement read =
                  db.prepareStatement(
                      "select version, body::text, received_at, received_from"
                          + " from egress.egress_grant_table where id = ?")) {
            read.setString(1, ID);
            try (ResultSet row = read.executeQuery()) {
              if (!row.next()) {
                return Optional.empty();
              }
              return Optional.of(
                  new Held(
                      row.getLong(1),
                      row.getString(2),
                      row.getObject(3, OffsetDateTime.class).toInstant(),
                      row.getString(4)));
            }
          } catch (SQLException e) {
            throw new IllegalStateException("reading the grant table failed", e);
          }
        });
  }

  /**
   * Store a pushed table when its version is above the held one.
   *
   * @param version the table's version
   * @param body the table as JSON
   * @param receivedFrom the pushing caller's principal
   */
  public Stored store(long version, String body, String receivedFrom) {
    return DbRetry.call(
        "store the grant table",
        () -> {
          try (Connection db = egress.getConnection();
              PreparedStatement upsert =
                  db.prepareStatement(
                      "insert into egress.egress_grant_table"
                          + " (id, version, body, received_at, received_from)"
                          + " values (?, ?, ?::jsonb, now(), ?)"
                          + " on conflict (id) do update set version = excluded.version,"
                          + " body = excluded.body, received_at = excluded.received_at,"
                          + " received_from = excluded.received_from"
                          + " where egress.egress_grant_table.version < excluded.version"
                          + " returning version")) {
            upsert.setString(1, ID);
            upsert.setLong(2, version);
            upsert.setString(3, body);
            upsert.setString(4, receivedFrom);
            try (ResultSet row = upsert.executeQuery()) {
              if (row.next()) {
                return new Stored(Outcome.STORED, row.getLong(1));
              }
            }
          } catch (SQLException e) {
            throw new IllegalStateException("storing the grant table failed", e);
          }
          long held = readVersion().orElseThrow(
              () -> new IllegalStateException("the grant table refused a write and holds none"));
          return new Stored(held == version ? Outcome.UNCHANGED : Outcome.OLDER, held);
        });
  }

  /** Forget the held table. For the suites' provider states; no door calls it. */
  public void clear() {
    DbRetry.run(
        "clear the grant table",
        () -> {
          try (Connection db = egress.getConnection();
              PreparedStatement delete =
                  db.prepareStatement("delete from egress.egress_grant_table where id = ?")) {
            delete.setString(1, ID);
            delete.executeUpdate();
          } catch (SQLException e) {
            throw new IllegalStateException("clearing the grant table failed", e);
          }
        });
  }

  private Optional<Long> readVersion() {
    try (Connection db = egress.getConnection();
        PreparedStatement read =
            db.prepareStatement("select version from egress.egress_grant_table where id = ?")) {
      read.setString(1, ID);
      try (ResultSet row = read.executeQuery()) {
        return row.next() ? Optional.of(row.getLong(1)) : Optional.empty();
      }
    } catch (SQLException e) {
      throw new IllegalStateException("reading the grant table's version failed", e);
    }
  }
}
