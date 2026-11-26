package eu.wohlben.qits.egress.api;

/**
 * The roles the grant-table door names.
 *
 * <ul>
 *   <li><b>{@code PUT}</b>: {@code qits:system}, and then only the deployer's own client ({@link
 *       GrantTablePublisher}).
 *   <li><b>{@code GET}</b>: the same publisher, and {@code qits:admin}, {@code qits:admin-agent},
 *       {@code qits:desk-admin} and {@code qits:agent} for people, the desk and agents. A
 *       {@code qits:system} caller holding none of those is held to the publisher check too: the
 *       read is for the deployer's read-back, not for every service.
 *   <li><b>{@code PUT /claude-credential}</b>: {@code qits:target-runner} only, the runner's idp
 *       client (qits-2664). <b>{@code GET}</b>: {@code qits:agent}, {@code qits:system}, {@code
 *       qits:admin} and {@code qits:target-runner}.
 * </ul>
 */
public final class Roles {

  public static final String SYSTEM = "qits:system";
  public static final String ADMIN = "qits:admin";
  public static final String ADMIN_AGENT = "qits:admin-agent";
  public static final String DESK_ADMIN = "qits:desk-admin";
  public static final String AGENT = "qits:agent";
  public static final String TARGET_RUNNER = "qits:target-runner";

  private Roles() {}
}
