package eu.wohlben.qits.egress.grants;

import eu.wohlben.qits.egress.api.GrantTableWire;
import java.net.URI;
import java.util.Locale;
import java.util.Set;
import java.util.TreeSet;
import java.util.regex.Pattern;

/**
 * One route of the table, compiled once when the table is adopted, so nothing on the request path
 * parses a target: the grant {@code (application, name, methods)} and where and how it goes.
 *
 * @param application the granted application ({@code application:<application>})
 * @param name the first path segment at the gateway
 * @param methods upper-case HTTP methods
 * @param platform the {@code platform:<label>} label, or null for an outside target; a platform
 *     route's target is the platform origin of that label ({@code qits.egress.platform.origin},
 *     {@code https://<label>.qits.${QITS_DOMAIN}})
 * @param ssl whether the target is {@code https}; plain {@code http} only under the test flag
 * @param host the target host
 * @param port the target port, or -1 for the scheme's default
 * @param basePath the target's path, no trailing slash, "" for none
 * @param secret the secret's name: its value is {@code QITS_EGRESS_SECRET_<secret>}
 * @param injectHeader the header the secret goes in
 * @param injectPrefix what precedes the secret in that header ({@code "Bearer "} or "")
 * @param problem why this route cannot be served (a bad target, a bad injection), or null
 * @param targetProblem why its TARGET cannot be dialled, or null: all a {@code CONNECT} needs, since a
 *     tunnel injects nothing
 */
public record GrantRoute(
    String application,
    String name,
    Set<String> methods,
    String platform,
    boolean ssl,
    String host,
    int port,
    String basePath,
    String secret,
    String injectHeader,
    String injectPrefix,
    String problem,
    String targetProblem) {

  static final String PLATFORM = "platform:";

  /** The platform origin template's placeholder for a label. */
  public static final String LABEL = "{label}";

  /** A platform label: what {@code <label>.qits.<domain>} allows. */
  private static final Pattern PLATFORM_LABEL = Pattern.compile("[a-z][a-z0-9-]{0,62}");

  /** The platform origin in a deployment; {@code qits.egress.platform.origin} says it. */
  static final String DEFAULT_PLATFORM_ORIGIN = "https://{label}.qits.wohlben.eu";

  /** RFC 9110 token characters: what a header name may be made of. */
  private static final Pattern TOKEN = Pattern.compile("[!#$%&'*+.^_`|~0-9A-Za-z-]+");

  private static final Pattern SECRET = Pattern.compile("[A-Z][A-Z0-9_]{0,63}");

  /** Whether the target is a platform service ({@code platform:<label>}, qits-2623). */
  public boolean isPlatform() {
    return platform != null;
  }

  /** {@code host[:port]}, for the {@code Host} header and the audit line. */
  public String authority() {
    return port < 0 ? host : host + ":" + port;
  }

  /** The port actually dialled. */
  public int dialPort() {
    return port >= 0 ? port : ssl ? 443 : 80;
  }

  /** {@code https} or {@code http}. */
  public String scheme() {
    return ssl ? "https" : "http";
  }

  /**
   * Compile one route of a pushed table.
   *
   * @param allowPlainHttp whether an {@code http://} target is served (the suites' fake upstream
   *     only; the deployer's parser refuses one, and so does this in a deployment)
   */
  static GrantRoute of(GrantTableWire.Route route, boolean allowPlainHttp) {
    return of(route, allowPlainHttp, DEFAULT_PLATFORM_ORIGIN);
  }

  /**
   * Compile one route of a pushed table.
   *
   * @param platformOrigin where {@code platform:<label>} goes, {@value #LABEL} standing for the
   *     label: {@code https://{label}.qits.${QITS_DOMAIN}} in a deployment
   */
  static GrantRoute of(GrantTableWire.Route route, boolean allowPlainHttp, String platformOrigin) {
    Set<String> methods = new TreeSet<>();
    route.methods().forEach(m -> methods.add(m.toUpperCase(Locale.ROOT)));
    String target = route.target() == null ? "" : route.target();
    if (target.startsWith(PLATFORM)) {
      String label = target.substring(PLATFORM.length());
      if (!PLATFORM_LABEL.matcher(label).matches()) {
        String problem = "the platform label is not [a-z][a-z0-9-]*";
        return new GrantRoute(
            route.application(), route.name(), Set.copyOf(methods), label, true, null, -1, "",
            null, null, null, problem, problem);
      }
      Target origin = Target.parse(platformOrigin.replace(LABEL, label), allowPlainHttp);
      return new GrantRoute(
          route.application(),
          route.name(),
          Set.copyOf(methods),
          label,
          origin.ssl(),
          origin.host(),
          origin.port(),
          origin.basePath(),
          null,
          null,
          null,
          origin.problem(),
          origin.problem());
    }
    Target parsed = Target.parse(target, allowPlainHttp);
    String problem = parsed.problem();
    String targetProblem = parsed.problem();
    boolean ssl = parsed.ssl();
    String host = parsed.host();
    int port = parsed.port();
    String basePath = parsed.basePath();
    String injectHeader = null;
    String injectPrefix = null;
    String inject = route.inject() == null ? "" : route.inject();
    if (inject.equals("bearer")) {
      injectHeader = "Authorization";
      injectPrefix = "Bearer ";
    } else if (inject.startsWith("header:")
        && TOKEN.matcher(inject.substring("header:".length())).matches()) {
      injectHeader = inject.substring("header:".length());
      injectPrefix = "";
    } else if (problem == null) {
      problem = "the injection is neither bearer nor header:<Name>";
    }
    if (route.secret() == null || !SECRET.matcher(route.secret()).matches()) {
      if (problem == null) {
        problem = "the secret name is not [A-Z][A-Z0-9_]*";
      }
    }
    return new GrantRoute(
        route.application(),
        route.name(),
        Set.copyOf(methods),
        null,
        ssl,
        host,
        port,
        basePath,
        route.secret(),
        injectHeader,
        injectPrefix,
        problem,
        targetProblem);
  }

  /** A target URL, parsed: where it goes, or why it cannot. */
  record Target(boolean ssl, String host, int port, String basePath, String problem) {

    static Target parse(String target, boolean allowPlainHttp) {
      String problem = null;
      boolean ssl = false;
      String host = null;
      int port = -1;
      String basePath = "";
      try {
        URI uri = URI.create(target);
        String scheme = uri.getScheme() == null ? "" : uri.getScheme().toLowerCase(Locale.ROOT);
        ssl = scheme.equals("https");
        if (!ssl && !(allowPlainHttp && scheme.equals("http"))) {
          problem = "the target is not https";
        }
        host = uri.getHost();
        port = uri.getPort();
        if (host == null || uri.getRawUserInfo() != null) {
          problem = "the target names no plain host";
        }
        if (uri.getRawQuery() != null || uri.getRawFragment() != null) {
          problem = "the target carries a query or a fragment";
        }
        basePath = uri.getRawPath() == null ? "" : uri.getRawPath();
        while (basePath.endsWith("/")) {
          basePath = basePath.substring(0, basePath.length() - 1);
        }
      } catch (IllegalArgumentException e) {
        problem = "the target is not a URI";
      }
      return new Target(ssl, host, port, basePath, problem);
    }
  }
}
