package eu.wohlben.qits.egress.proxy;

import io.vertx.core.Future;
import io.vertx.core.http.HttpHeaders;
import io.vertx.core.net.HostAndPort;
import io.vertx.httpproxy.ProxyContext;
import io.vertx.httpproxy.ProxyInterceptor;
import io.vertx.httpproxy.ProxyRequest;
import io.vertx.httpproxy.ProxyResponse;

/**
 * <b>What leaves for a passthrough {@code http://} target</b> ({@link Passthrough}): the request as
 * the caller sent it, to the name it asked for. Only {@code Proxy-Authorization} — the credential
 * for THIS proxy — is removed here; {@link EdgeHopByHop} removes the hop-by-hop set. The caller's
 * own {@code Authorization} and {@code Cookie} stay: they are the caller's for its target, not the
 * platform's. Nothing is injected and nothing is scrubbed, and {@link EgressOutbound}'s strip never
 * runs here.
 */
final class PassthroughOutbound implements ProxyInterceptor {

  private final AbsoluteTarget target;

  private final String uri;

  private final AuditLine audit;

  /**
   * @param target the absolute-form target
   * @param uri the upstream request target: the path and the query
   * @param audit the call's audit line
   */
  PassthroughOutbound(AbsoluteTarget target, String uri, AuditLine audit) {
    this.target = target;
    this.uri = uri;
    this.audit = audit;
  }

  @Override
  public Future<ProxyResponse> handleProxyRequest(ProxyContext context) {
    ProxyRequest request = context.request();
    request.setURI(uri);
    request.setAuthority(HostAndPort.create(target.host(), target.port()));
    request.headers().remove(HttpHeaders.PROXY_AUTHORIZATION);
    request.headers().remove(HttpHeaders.HOST);
    return context.sendRequest();
  }

  @Override
  public Future<Void> handleProxyResponse(ProxyContext context) {
    audit.upstreamAnswered();
    return context.sendResponse();
  }
}
