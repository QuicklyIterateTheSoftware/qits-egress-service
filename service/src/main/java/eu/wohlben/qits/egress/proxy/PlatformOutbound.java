package eu.wohlben.qits.egress.proxy;

import eu.wohlben.qits.egress.grants.GrantRoute;
import io.vertx.core.Future;
import io.vertx.core.MultiMap;
import io.vertx.core.http.HttpHeaders;
import io.vertx.core.net.HostAndPort;
import io.vertx.httpproxy.ProxyContext;
import io.vertx.httpproxy.ProxyInterceptor;
import io.vertx.httpproxy.ProxyResponse;

/**
 * <b>What leaves the gateway for a platform route</b>: the platform service's path and {@code
 * Host}, none of the caller's credentials or platform headers (exactly {@link EgressOutbound}'s
 * strip), and {@code Authorization: Bearer <the caller's bearer exchanged at qits-idp>}.
 *
 * <p><b>The exchanged bearer is for a platform target only</b>: this interceptor refuses to be built
 * for a route that is not {@code platform:<label>}, whose target is the platform origin {@code
 * https://<label>.qits.${QITS_DOMAIN}}. A third-party route goes through {@link EgressOutbound},
 * which removes every {@code Authorization} and writes the route's secret; nothing there ever
 * holds an exchanged token. No scrubbing here: there is no secret to take out.
 */
final class PlatformOutbound implements ProxyInterceptor {

  private final GrantRoute route;

  private final String uri;

  private final String bearer;

  private final AuditLine audit;

  /**
   * @throws IllegalArgumentException for a route that is not a platform route
   */
  PlatformOutbound(GrantRoute route, String uri, String bearer, AuditLine audit) {
    if (!route.isPlatform()) {
      throw new IllegalArgumentException(
          "an exchanged bearer goes to a platform route's target only, never to " + route.name());
    }
    this.route = route;
    this.uri = uri;
    this.bearer = bearer;
    this.audit = audit;
  }

  @Override
  public Future<ProxyResponse> handleProxyRequest(ProxyContext context) {
    context.request().setURI(uri);
    context.request().setAuthority(HostAndPort.create(route.host(), route.port()));
    authorize(context.request().headers(), route, bearer);
    return context.sendRequest();
  }

  @Override
  public Future<Void> handleProxyResponse(ProxyContext context) {
    audit.upstreamAnswered();
    return context.sendResponse();
  }

  /** The caller's credentials out, the exchanged bearer in — for a platform route only. */
  static void authorize(MultiMap headers, GrantRoute route, String bearer) {
    if (!route.isPlatform()) {
      throw new IllegalArgumentException("an exchanged bearer goes to a platform target only");
    }
    EgressOutbound.strip(headers);
    headers.set(HttpHeaders.AUTHORIZATION, "Bearer " + bearer);
  }
}
