package eu.wohlben.qits.egress.identity;

import eu.wohlben.qits.auth.WorkloadPrincipal;
import io.vertx.core.json.JsonObject;

/**
 * Who a validated caller is, as the grant table names callers.
 *
 * <ul>
 *   <li>{@code application:<application>} — a platform service's own client token: {@code sub} is
 *       {@code ${QITS_ENVIRONMENT}-<application>} and {@code groups} hold both {@code clients/<sub>}
 *       and {@code qits:system};
 *   <li>else {@code agent:<agent claim>}, else {@code project:<project claim>}, else {@code
 *       subject:<sub>}.
 * </ul>
 *
 * <p>An {@code agent:} principal keeps the token's {@code project} claim (qits-2525): an agent
 * belongs to its project, and is granted what its project is ({@link #project()}). The printed form
 * is still {@code agent:<agent>}, so the audit line names the agent.
 *
 * <p>The table holds routes of {@code application:} and {@code project:} principals (qits-2525): a
 * caller holds its own principal's routes and, as an {@code agent:}, its project's ({@code
 * grants/GrantIndex.Table#holders}). A principal with a project gets the passthrough ({@code
 * proxy/Passthrough}) for what no route matches; an application never does.
 *
 * @param kind {@code application}, {@code agent}, {@code project} or {@code subject}
 * @param name what follows the colon
 * @param project the project the principal belongs to: its name for a {@code project:} principal,
 *     the token's {@code project} claim for an {@code agent:} one, null otherwise
 */
public record Principal(String kind, String name, String project) {

  public static final String APPLICATION = "application";

  public static final String AGENT = "agent";

  public static final String PROJECT = "project";

  /** A principal of no project but the one a {@code project:} principal is. */
  public Principal(String kind, String name) {
    this(kind, name, PROJECT.equals(kind) ? name : null);
  }

  /** The application this principal is, or null when it is not one. */
  public String application() {
    return APPLICATION.equals(kind) ? name : null;
  }

  /**
   * The project this principal belongs to — a {@code project:} principal's own name, an {@code
   * agent:} principal's {@code project} claim — or null: an application, a subject, an agent token
   * without a project.
   */
  @Override
  public String project() {
    return APPLICATION.equals(kind) ? null : project;
  }

  @Override
  public String toString() {
    return kind + ":" + name;
  }

  /**
   * Map a validated token's claims to a principal: qits-auth-core's {@link
   * WorkloadPrincipal#fromClaims}, the one copy of the grammar the workload certificates are issued
   * and read in (epic qits-2626, qits-2755; the rules moved there unchanged).
   *
   * @param environment {@code QITS_ENVIRONMENT}, the prefix of every service client's id
   */
  public static Principal of(JsonObject claims, String environment) {
    return of(WorkloadPrincipal.fromClaims(claims.getMap(), environment));
  }

  /** The same principal in this service's type. */
  public static Principal of(WorkloadPrincipal principal) {
    return new Principal(principal.kind(), principal.name(), principal.project());
  }
}
