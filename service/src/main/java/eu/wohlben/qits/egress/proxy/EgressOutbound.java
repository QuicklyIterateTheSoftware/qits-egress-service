package eu.wohlben.qits.egress.proxy;

import eu.wohlben.qits.egress.grants.GrantRoute;
import io.vertx.core.Future;
import io.vertx.core.MultiMap;
import io.vertx.core.http.HttpHeaders;
import io.vertx.core.net.HostAndPort;
import io.vertx.httpproxy.ProxyContext;
import io.vertx.httpproxy.ProxyInterceptor;
import io.vertx.httpproxy.ProxyRequest;
import io.vertx.httpproxy.ProxyResponse;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;

/**
 * <b>What leaves the gateway for one granted call</b>: the target's path and {@code Host}, NONE of
 * the caller's credentials, and the route's secret in the one header it is for.
 *
 * <p>Removed from the outbound copy of the request: {@code Authorization}, {@code
 * Proxy-Authorization}, {@code Cookie} and every {@code X-Qits-*} header — the caller's identity
 * and platform context are the platform's, never a third party's. The hop-by-hop set goes in {@link
 * EdgeHopByHop}, next in the chain. Then the secret: {@code inject: bearer} writes {@code
 * Authorization: Bearer <secret>}, {@code inject: header:<Name>} writes {@code <Name>: <secret>},
 * {@code inject: cookie:<name>} writes {@code Cookie: <name>=<secret>} — the whole header, since the
 * caller's own {@code Cookie} was stripped first.
 *
 * <p>First in the chain, so every later interceptor (and {@link UpstreamRetry}'s second attempt)
 * sends what this one wrote. Its response hook records that the upstream answered, which the audit
 * line uses to tell an upstream's status from the proxy's own 502.
 */
final class EgressOutbound implements ProxyInterceptor {

  /** The caller's credentials, which never leave the platform. */
  static final List<String> CALLER_CREDENTIALS =
      List.of("Authorization", "Proxy-Authorization", "Cookie");

  static final String PLATFORM_HEADER_PREFIX = "x-qits-";

  private final GrantRoute route;

  private final String uri;

  private final String secret;

  private final AuditLine audit;

  /**
   * @param route the granted route
   * @param uri the upstream request target: the route's base path, the rest and the query
   * @param secret the route's secret value
   * @param audit the call's audit line
   */
  EgressOutbound(GrantRoute route, String uri, String secret, AuditLine audit) {
    this.route = route;
    this.uri = uri;
    this.secret = secret;
    this.audit = audit;
  }

  @Override
  public Future<ProxyResponse> handleProxyRequest(ProxyContext context) {
    ProxyRequest request = context.request();
    request.setURI(uri);
    request.setAuthority(HostAndPort.create(route.host(), route.port()));
    strip(request.headers());
    inject(request.headers(), route, secret);
    return context.sendRequest();
  }

  /** The route's secret in the one header it is for. */
  static void inject(MultiMap headers, GrantRoute route, String secret) {
    headers.set(route.injectHeader(), route.injectPrefix() + secret);
  }

  @Override
  public Future<Void> handleProxyResponse(ProxyContext context) {
    audit.upstreamAnswered();
    return context.sendResponse();
  }

  /** Remove the caller's credentials and every platform header. Static for the tests. */
  static void strip(MultiMap headers) {
    CALLER_CREDENTIALS.forEach(headers::remove);
    headers.remove(HttpHeaders.HOST);
    List<String> platform = new ArrayList<>();
    for (String name : headers.names()) {
      if (name.toLowerCase(Locale.ROOT).startsWith(PLATFORM_HEADER_PREFIX)) {
        platform.add(name);
      }
    }
    platform.forEach(headers::remove);
  }
}
