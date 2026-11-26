package eu.wohlben.qits.egress.api;

import com.fasterxml.jackson.annotation.JsonCreator;
import java.time.Instant;
import java.util.List;

/**
 * Everything the grant-table door binds and answers. The table is exactly the deployer's
 * ({@code EgressGrantTableDto} of qits-deployments, served at {@code GET
 * /deployments/api/egress-grants}): what it pushes is what it serves, field for field.
 */
public final class GrantTableWire {

  private GrantTableWire() {}

  /**
   * The table qits-deployments pushes.
   *
   * @param version only ever goes up, and moves only when the content does
   * @param routes every granted route
   * @param refused every ACTIVE deployment whose declaration was refused
   */
  public record GrantTable(long version, List<Route> routes, List<Refused> refused) {

    public GrantTable {
      routes = routes == null ? List.of() : List.copyOf(routes);
      refused = refused == null ? List.of() : List.copyOf(refused);
    }
  }

  /** The principal an application's routes are granted to: {@code application:<application>}. */
  public static final String APPLICATION_PRINCIPAL = "application:";

  /**
   * Who an entry is for: {@code principal} as pushed, or, for a table pushed before qits-2659 named
   * one, {@code application:<application>}; null when neither is there.
   */
  static String principalOf(String principal, String application) {
    if (principal != null && !principal.isBlank()) {
      return principal;
    }
    return application == null || application.isBlank() ? null : APPLICATION_PRINCIPAL + application;
  }

  /**
   * One granted route: the grant {@code (principal, name, methods)}.
   *
   * @param principal who it is granted to: {@code application:<application>} or {@code
   *     project:<projectId>} (qits-2525); absent in a table older than qits-2659, and then {@code
   *     application:<application>}, so the held table always names it
   * @param application the application, for an application route; null for a project route
   * @param target {@code https://<host>[:port][/base path]} or {@code platform:<label>}
   * @param secret the name whose value is {@code QITS_EGRESS_SECRET_<secret>} (a project route's is
   *     already resolved, {@code PROJECT_<SLUG>_<name>}); null for a platform target
   * @param inject {@code bearer}, {@code header:<Header-Name>} or {@code cookie:<name>}; null for a
   *     platform target
   */
  public record Route(
      String principal,
      String application,
      String environment,
      String deployedVersion,
      String name,
      String target,
      String secret,
      String inject,
      List<String> methods) {

    /** What Jackson binds: the canonical constructor, never the older shape's. */
    @JsonCreator
    public Route {
      principal = principalOf(principal, application);
      methods = methods == null ? List.of() : List.copyOf(methods);
    }

    /** An application route, as a table older than qits-2659 carried it. */
    public Route(
        String application,
        String environment,
        String deployedVersion,
        String name,
        String target,
        String secret,
        String inject,
        List<String> methods) {
      this(
          null, application, environment, deployedVersion, name, target, secret, inject, methods);
    }
  }

  /**
   * An ACTIVE deployment — or a project's wrapper — whose egress declaration was refused, and why.
   *
   * @param principal as for {@link Route#principal()}, with the same fallback
   */
  public record Refused(
      String principal, String application, String deployedVersion, String reason) {

    @JsonCreator
    public Refused {
      principal = principalOf(principal, application);
    }

    /** An application's refusal, as a table older than qits-2659 carried it. */
    public Refused(String application, String deployedVersion, String reason) {
      this(null, application, deployedVersion, reason);
    }
  }

  /** What {@code GET /egress/api/grant-table} answers: the held table and when it arrived. */
  public record HeldTable(
      long version, Instant receivedAt, List<Route> routes, List<Refused> refused) {}

  /** Every refusal the door writes itself. */
  public record ErrorBody(String error) {}

  /** A push older than the held table: refused, and the version held. */
  public record OlderTable(String error, long held) {}
}
