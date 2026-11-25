package eu.wohlben.qits.egress.grants;

import com.fasterxml.jackson.databind.ObjectMapper;
import eu.wohlben.qits.egress.api.GrantTableWire;
import eu.wohlben.qits.egress.store.GrantTableStore;
import io.quarkus.runtime.ShutdownEvent;
import io.quarkus.runtime.StartupEvent;
import io.vertx.core.Vertx;
import jakarta.enterprise.context.ApplicationScoped;
import jakarta.enterprise.event.Observes;
import jakarta.inject.Inject;
import java.io.IOException;
import java.io.UncheckedIOException;
import java.time.Duration;
import java.util.HashMap;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.atomic.AtomicBoolean;
import org.eclipse.microprofile.config.inject.ConfigProperty;
import org.jboss.logging.Logger;

/**
 * <b>The grant table this replica enforces</b>: an immutable index {@code (application, route
 * name) → route}, replaced whole and never mutated, so a request reads one consistent table without
 * a lock.
 *
 * <p><b>How the two replicas agree.</b> The push lands on one of them ({@code PUT
 * /egress/api/grant-table}), which stores it in the shared database and adopts it at once. Every
 * replica loads the stored table at boot and then, every {@code qits.egress.grants.refresh} (5 s),
 * reads the held VERSION — one indexed row — and re-reads the body only when it differs from the one
 * in memory. So a push is enforced everywhere within one refresh, and the steady state costs a
 * one-column read per replica per interval.
 *
 * <p><b>Readiness never waits for it.</b> With no table held, {@link #current()} is null and the
 * proxy answers every call 503 "no grant table yet"; the first deployment must pass its gate before
 * the deployer has anything to push to. A refresh that fails (the database moving) keeps the table
 * in memory and logs a WARN; the next tick tries again.
 */
@ApplicationScoped
public class GrantIndex {

  private static final Logger LOG = Logger.getLogger(GrantIndex.class);

  /** One adopted table. */
  public record Table(long version, Map<String, Map<String, GrantRoute>> routes) {

    /** The route {@code name} granted to {@code application}, or null. */
    public GrantRoute route(String application, String name) {
      if (application == null || name == null) {
        return null;
      }
      Map<String, GrantRoute> granted = routes.get(application);
      return granted == null ? null : granted.get(name);
    }

    /** Every route granted to {@code application}, in no particular order; empty for none. */
    public java.util.Collection<GrantRoute> routes(String application) {
      if (application == null) {
        return java.util.List.of();
      }
      Map<String, GrantRoute> granted = routes.get(application);
      return granted == null ? java.util.List.of() : granted.values();
    }
  }

  @Inject GrantTableStore store;

  @Inject ObjectMapper json;

  @Inject Vertx vertx;

  @ConfigProperty(name = "qits.egress.grants.refresh", defaultValue = "5s")
  Duration refresh;

  @ConfigProperty(name = "qits.egress.test.allow-plain-http", defaultValue = "false")
  boolean allowPlainHttp;

  /** Where {@code platform:<label>} goes: {@code https://{label}.qits.${QITS_DOMAIN}}. */
  @ConfigProperty(name = "qits.egress.platform.origin")
  String platformOrigin;

  private volatile Table current;

  private long timer = -1;

  private final AtomicBoolean refreshing = new AtomicBoolean();

  /** The table in force, or null while none is held. */
  public Table current() {
    return current;
  }

  void start(@Observes StartupEvent ignored) {
    try {
      refresh();
    } catch (RuntimeException e) {
      LOG.warnf("could not load the grant table at boot, retrying every %s: %s", refresh, e);
    }
    timer =
        vertx.setPeriodic(
            refresh.toMillis(),
            id -> {
              // A database that hangs must not stack one blocked worker per tick.
              if (!refreshing.compareAndSet(false, true)) {
                return;
              }
              vertx
                  .executeBlocking(
                      () -> {
                        refresh();
                        return null;
                      },
                      false)
                  .onComplete(done -> refreshing.set(false))
                  .onFailure(
                      e ->
                          LOG.warnf(
                              "could not refresh the grant table, keeping %s: %s",
                              describe(current), e));
            });
  }

  void stop(@Observes ShutdownEvent ignored) {
    if (timer >= 0) {
      vertx.cancelTimer(timer);
    }
  }

  /**
   * Compare the held version with the one in memory and re-read the table when they differ.
   * Blocking: a database read.
   */
  public synchronized void refresh() {
    Optional<Long> held = store.version();
    Table known = current;
    if (held.isEmpty()) {
      if (known != null) {
        LOG.warnf("the grant table %d is no longer held: every call is refused", known.version());
      }
      current = null;
      return;
    }
    if (known != null && known.version() == held.get()) {
      return;
    }
    // The database is the truth: whatever it holds replaces memory, even a lower version.
    store
        .held()
        .ifPresentOrElse(
            row -> {
              current = index(parse(row.body()), allowPlainHttp, platformOrigin);
              LOG.infof("enforcing %s", describe(current));
            },
            () -> current = null);
  }

  /**
   * Serve a table this replica just stored, unless a newer one is already in memory (a refresh
   * that ran in between).
   */
  public synchronized void adopt(GrantTableWire.GrantTable table) {
    Table known = current;
    if (known != null && known.version() >= table.version()) {
      return;
    }
    current = index(table, allowPlainHttp, platformOrigin);
    LOG.infof("enforcing %s", describe(current));
  }

  /** The stored body as the wire type. */
  public GrantTableWire.GrantTable parse(String body) {
    try {
      return json.readValue(body, GrantTableWire.GrantTable.class);
    } catch (IOException e) {
      throw new UncheckedIOException("the stored grant table is unreadable", e);
    }
  }

  /**
   * Compile a table. A route without an application or a name cannot be looked up and is dropped;
   * a second route of one name for one application (two environments in one table) keeps the first.
   * Package-visible and static so it is asserted alone.
   */
  static Table index(GrantTableWire.GrantTable table, boolean allowPlainHttp) {
    return index(table, allowPlainHttp, GrantRoute.DEFAULT_PLATFORM_ORIGIN);
  }

  public static Table index(
      GrantTableWire.GrantTable table, boolean allowPlainHttp, String platformOrigin) {
    Map<String, Map<String, GrantRoute>> routes = new HashMap<>();
    for (GrantTableWire.Route route : table.routes()) {
      if (route.application() == null || route.name() == null) {
        LOG.warnf("table %d: a route without an application or a name is dropped", table.version());
        continue;
      }
      GrantRoute compiled = GrantRoute.of(route, allowPlainHttp, platformOrigin);
      if (compiled.problem() != null) {
        LOG.warnf(
            "table %d: route %s of %s cannot be served: %s",
            table.version(), route.name(), route.application(), compiled.problem());
      }
      GrantRoute first =
          routes
              .computeIfAbsent(route.application(), k -> new HashMap<>())
              .putIfAbsent(route.name(), compiled);
      if (first != null) {
        LOG.warnf(
            "table %d: route %s of %s is declared twice; the first is served",
            table.version(), route.name(), route.application());
      }
    }
    Map<String, Map<String, GrantRoute>> frozen = new HashMap<>();
    routes.forEach((application, named) -> frozen.put(application, Map.copyOf(named)));
    return new Table(table.version(), Map.copyOf(frozen));
  }

  private static String describe(Table table) {
    if (table == null) {
      return "no grant table";
    }
    int count = table.routes().values().stream().mapToInt(Map::size).sum();
    return "grant table " + table.version() + " (" + count + " routes)";
  }
}
