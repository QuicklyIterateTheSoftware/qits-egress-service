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
 * @param platform the {@code platform:<label>} label, or null for an outside target
 * @param ssl whether the target is {@code https}; plain {@code http} only under the test flag
 * @param host the target host
 * @param port the target port, or -1 for the scheme's default
 * @param basePath the target's path, no trailing slash, "" for none
 * @param secret the secret's name: its value is {@code QITS_EGRESS_SECRET_<secret>}
 * @param injectHeader the header the secret goes in
 * @param injectPrefix what precedes the secret in that header ({@code "Bearer "} or "")
 * @param problem why this route cannot be served (a bad target, a bad injection), or null
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
    String problem) {

  static final String PLATFORM = "platform:";

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

  /**
   * Compile one route of a pushed table.
   *
   * @param allowPlainHttp whether an {@code http://} target is served (the suites' fake upstream
   *     only; the deployer's parser refuses one, and so does this in a deployment)
   */
  static GrantRoute of(GrantTableWire.Route route, boolean allowPlainHttp) {
    Set<String> methods = new TreeSet<>();
    route.methods().forEach(m -> methods.add(m.toUpperCase(Locale.ROOT)));
    String target = route.target() == null ? "" : route.target();
    if (target.startsWith(PLATFORM)) {
      return new GrantRoute(
          route.application(),
          route.name(),
          Set.copyOf(methods),
          target.substring(PLATFORM.length()),
          true,
          null,
          -1,
          "",
          null,
          null,
          null,
          null);
    }
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
        problem);
  }
}
