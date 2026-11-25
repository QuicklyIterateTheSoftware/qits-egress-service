package eu.wohlben.qits.egress.identity;

import io.vertx.core.json.JsonArray;
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
 * <p>Only an {@code application:} principal matches routes: the table holds application routes only
 * (qits-2525 adds declarations for the others).
 *
 * @param kind {@code application}, {@code agent}, {@code project} or {@code subject}
 * @param name what follows the colon
 */
public record Principal(String kind, String name) {

  public static final String APPLICATION = "application";

  /** The application this principal is, or null when it is not one. */
  public String application() {
    return APPLICATION.equals(kind) ? name : null;
  }

  @Override
  public String toString() {
    return kind + ":" + name;
  }

  /**
   * Map a validated token's claims to a principal.
   *
   * @param environment {@code QITS_ENVIRONMENT}, the prefix of every service client's id
   */
  public static Principal of(JsonObject claims, String environment) {
    String subject = text(claims.getValue("sub"));
    JsonArray groups = groups(claims.getValue("groups"));
    String prefix = environment + "-";
    if (subject != null
        && subject.startsWith(prefix)
        && subject.length() > prefix.length()
        && groups.contains("clients/" + subject)
        && groups.contains("qits:system")) {
      return new Principal(APPLICATION, subject.substring(prefix.length()));
    }
    String agent = text(claims.getValue("agent"));
    if (agent != null) {
      return new Principal("agent", agent);
    }
    String project = text(claims.getValue("project"));
    if (project != null) {
      return new Principal("project", project);
    }
    return new Principal("subject", subject == null ? "-" : subject);
  }

  private static JsonArray groups(Object value) {
    if (value instanceof JsonArray array) {
      return array;
    }
    return value == null ? new JsonArray() : new JsonArray().add(value);
  }

  private static String text(Object value) {
    if (value == null) {
      return null;
    }
    String text = value.toString();
    return text.isBlank() ? null : text;
  }
}
