package eu.wohlben.qits.egress.proxy;

import io.vertx.core.Future;
import io.vertx.core.MultiMap;
import io.vertx.core.buffer.Buffer;
import io.vertx.core.http.HttpHeaders;
import io.vertx.core.net.HostAndPort;
import io.vertx.httpproxy.Body;
import io.vertx.httpproxy.ProxyContext;
import io.vertx.httpproxy.ProxyInterceptor;
import io.vertx.httpproxy.ProxyRequest;
import io.vertx.httpproxy.ProxyResponse;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;

/**
 * <b>What leaves for a Claude host</b> ({@link ClaudeHosts}, qits-2664): the request as Claude Code
 * sent it, with ONE change — {@code Authorization: Bearer qits-egress-placeholder} becomes {@code
 * Bearer <the held access token>}. Any other {@code Authorization} (a container not cut over yet,
 * holding its own login) and the caller's {@code Cookie} go out unchanged: they are the caller's.
 * Removed: {@code Proxy-Authorization} (this proxy's credential), every {@code X-Qits-*} header (the
 * platform's context, never a third party's) and, in {@link EdgeHopByHop}, the hop-by-hop set.
 *
 * <p>{@code POST /v1/oauth/token} was read whole to look for the placeholder refresh; when it is a
 * real one it leaves with that body ({@link Body#body(Buffer)}).
 */
final class ClaudeOutbound implements ProxyInterceptor {

  private final String host;

  private final String uri;

  private final String accessToken;

  private final Buffer body;

  private final AuditLine audit;

  /**
   * @param host the Claude host, for {@code Host}
   * @param uri the upstream request target: the path and the query
   * @param accessToken the held access token when the caller sent the placeholder, else null
   * @param body the request body when it was already read, else null (streamed)
   */
  ClaudeOutbound(String host, String uri, String accessToken, Buffer body, AuditLine audit) {
    this.host = host;
    this.uri = uri;
    this.accessToken = accessToken;
    this.body = body;
    this.audit = audit;
  }

  @Override
  public Future<ProxyResponse> handleProxyRequest(ProxyContext context) {
    ProxyRequest request = context.request();
    request.setURI(uri);
    request.setAuthority(HostAndPort.create(host, -1));
    prepare(request.headers(), accessToken);
    if (body != null) {
      request.setBody(Body.body(body));
    }
    return context.sendRequest();
  }

  @Override
  public Future<Void> handleProxyResponse(ProxyContext context) {
    audit.upstreamAnswered();
    return context.sendResponse();
  }

  /** The headers a Claude host sees, in place. Static for the WebSocket handshake and the tests. */
  static void prepare(MultiMap headers, String accessToken) {
    headers.remove(HttpHeaders.PROXY_AUTHORIZATION);
    headers.remove(HttpHeaders.HOST);
    List<String> platform = new ArrayList<>();
    for (String name : headers.names()) {
      if (name.toLowerCase(Locale.ROOT).startsWith(EgressOutbound.PLATFORM_HEADER_PREFIX)) {
        platform.add(name);
      }
    }
    platform.forEach(headers::remove);
    if (accessToken != null) {
      headers.set(HttpHeaders.AUTHORIZATION, "Bearer " + accessToken);
    }
  }

  /** A WebSocket handshake's headers: {@link #prepare}d, the hop-by-hop set gone but {@code Upgrade}. */
  static MultiMap handshake(MultiMap inbound, String accessToken) {
    MultiMap outbound = MultiMap.caseInsensitiveMultiMap().addAll(inbound);
    String upgrade = outbound.get(HttpHeaders.UPGRADE);
    prepare(outbound, accessToken);
    EdgeHopByHop.strip(outbound);
    if (upgrade != null) {
      outbound.set(HttpHeaders.UPGRADE, upgrade);
    }
    return outbound;
  }
}
