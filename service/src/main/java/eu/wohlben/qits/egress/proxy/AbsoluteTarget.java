package eu.wohlben.qits.egress.proxy;

import eu.wohlben.qits.egress.grants.GrantRoute;
import java.net.URI;
import java.util.Collection;
import java.util.Locale;

/**
 * <b>An absolute-form request target</b> — {@code GET http://host/path} or {@code GET
 * https://host/path}, what an {@code HTTP_PROXY}/{@code HTTPS_PROXY} client sends a proxy — and the
 * granted route it is for.
 *
 * <p><b>Matching.</b> A route matches when its target ORIGIN is the request's — scheme, host
 * (case folded) and port, each scheme's default filled in — and its base path prefixes the request's
 * path on a segment boundary; of several, the longest base path. A platform route's origin is
 * {@code https://<label>.qits.${QITS_DOMAIN}}.
 *
 * <p><b>{@code http://} for an {@code https://} route.</b> A proxy client tunnels every {@code
 * https://} URL with {@code CONNECT}, where nothing can be injected; to have the secret injected it
 * sends {@code http://host/…} instead, on qits-net, and the gateway is the TLS client. So {@code
 * http://host[:80]} also matches a route {@code https://host[:443]}, and the call leaves over TLS
 * exactly as the route says. Nothing ever leaves in plain http that the route did not declare.
 *
 * @param scheme {@code http} or {@code https}
 * @param host the host, lower case
 * @param port the port, the scheme's default filled in
 * @param path the raw path, {@code /} when empty
 * @param query the raw query, or null
 */
record AbsoluteTarget(String scheme, String host, int port, String path, String query) {

  /** Whether a request-target is absolute-form, by its scheme. */
  static boolean isAbsolute(String uri) {
    if (uri == null) {
      return false;
    }
    String lower = uri.length() > 8 ? uri.substring(0, 8).toLowerCase(Locale.ROOT) : uri.toLowerCase(Locale.ROOT);
    return lower.startsWith("http://") || lower.startsWith("https://");
  }

  /** Parse an absolute-form target, or null when it is not a plain http(s) URL. */
  static AbsoluteTarget parse(String uri) {
    try {
      URI parsed = URI.create(uri);
      String scheme = parsed.getScheme() == null ? "" : parsed.getScheme().toLowerCase(Locale.ROOT);
      if (!scheme.equals("http") && !scheme.equals("https")) {
        return null;
      }
      if (parsed.getHost() == null || parsed.getRawUserInfo() != null || parsed.getRawFragment() != null) {
        return null;
      }
      int port = parsed.getPort() >= 0 ? parsed.getPort() : scheme.equals("https") ? 443 : 80;
      String path = parsed.getRawPath() == null || parsed.getRawPath().isEmpty() ? "/" : parsed.getRawPath();
      return new AbsoluteTarget(
          scheme, parsed.getHost().toLowerCase(Locale.ROOT), port, path, parsed.getRawQuery());
    } catch (IllegalArgumentException notAUri) {
      return null;
    }
  }

  /** {@code scheme://host[:port]}, for the 403 body. */
  String origin() {
    boolean defaultPort = scheme.equals("https") ? port == 443 : port == 80;
    return scheme + "://" + host + (defaultPort ? "" : ":" + port);
  }

  /** The granted route this target is for, or null. */
  GrantRoute match(Collection<GrantRoute> routes) {
    GrantRoute best = null;
    for (GrantRoute route : routes) {
      if (route.targetProblem() != null || !sameOrigin(route) || !under(route.basePath())) {
        continue;
      }
      if (best == null || route.basePath().length() > best.basePath().length()) {
        best = route;
      }
    }
    return best;
  }

  private boolean sameOrigin(GrantRoute route) {
    if (route.host() == null || !route.host().equalsIgnoreCase(host)) {
      return false;
    }
    if (scheme.equals(route.scheme())) {
      return port == route.dialPort();
    }
    // http://host[:80] for an https://host[:443] route: the gateway is the TLS client.
    return scheme.equals("http") && route.ssl() && port == 80 && route.dialPort() == 443;
  }

  /** Whether {@code basePath} prefixes the path on a segment boundary ("" prefixes everything). */
  boolean under(String basePath) {
    if (basePath.isEmpty()) {
      return true;
    }
    return path.equals(basePath) || path.startsWith(basePath + "/");
  }
}
