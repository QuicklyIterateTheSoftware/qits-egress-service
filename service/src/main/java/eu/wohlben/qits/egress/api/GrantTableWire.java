package eu.wohlben.qits.egress.api;

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

  /**
   * One granted route: the grant {@code (application:<application>, name, methods)}.
   *
   * @param target {@code https://<host>[:port][/base path]} or {@code platform:<label>}
   * @param secret the name whose value is {@code QITS_EGRESS_SECRET_<secret>}; null for a platform
   *     target
   * @param inject {@code bearer} or {@code header:<Header-Name>}; null for a platform target
   */
  public record Route(
      String application,
      String environment,
      String deployedVersion,
      String name,
      String target,
      String secret,
      String inject,
      List<String> methods) {

    public Route {
      methods = methods == null ? List.of() : List.copyOf(methods);
    }
  }

  /** An ACTIVE deployment whose egress declaration was refused, and why. */
  public record Refused(String application, String deployedVersion, String reason) {}

  /** What {@code GET /egress/api/grant-table} answers: the held table and when it arrived. */
  public record HeldTable(
      long version, Instant receivedAt, List<Route> routes, List<Refused> refused) {}

  /** Every refusal the door writes itself. */
  public record ErrorBody(String error) {}

  /** A push older than the held table: refused, and the version held. */
  public record OlderTable(String error, long held) {}
}
