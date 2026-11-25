package eu.wohlben.qits.egress.proxy;

import io.vertx.core.Future;
import io.vertx.core.buffer.Buffer;
import io.vertx.core.http.HttpHeaders;
import io.vertx.core.http.HttpMethod;
import io.vertx.core.json.JsonObject;
import io.vertx.httpproxy.Body;
import io.vertx.httpproxy.ProxyContext;
import io.vertx.httpproxy.ProxyInterceptor;
import io.vertx.httpproxy.ProxyResponse;

/**
 * <b>A secret route's answer, scrubbed</b> ({@link Scrubber}): the request asks for {@code
 * Accept-Encoding: identity}, so the body is readable; every response header value is scrubbed,
 * {@code Location} included; the body is streamed through {@link ScrubbingReadStream}, and its
 * {@code Content-Length} goes, since a replacement changes it — the answer leaves chunked.
 *
 * <p><b>An encoded answer is refused</b>: an upstream that compresses whatever it was asked for
 * sends bytes the window cannot read, and passing them on would pass the secret on with them. The
 * caller gets 502 {@code {"error":"the upstream answered with a content encoding"}}, the audit
 * line ALLOW with reason {@code upstream-encoded}.
 *
 * <p>Not for platform routes, which inject no secret and so have none to take out.
 */
final class ResponseScrub implements ProxyInterceptor {

  private final Scrubber scrubber;

  private final AuditLine audit;

  ResponseScrub(Scrubber scrubber, AuditLine audit) {
    this.scrubber = scrubber;
    this.audit = audit;
  }

  @Override
  public Future<ProxyResponse> handleProxyRequest(ProxyContext context) {
    context.request().headers().set(HttpHeaders.ACCEPT_ENCODING, HttpHeaders.IDENTITY);
    return context.sendRequest();
  }

  @Override
  public Future<Void> handleProxyResponse(ProxyContext context) {
    ProxyResponse response = context.response();
    String encoding = response.headers().get(HttpHeaders.CONTENT_ENCODING);
    if (encoding != null && !encoding.isBlank()
        && !encoding.trim().equalsIgnoreCase("identity")) {
      audit.reason("upstream-encoded");
      response.release();
      response.headers().clear();
      response.setStatusCode(502);
      response.setStatusMessage("Bad Gateway");
      response.putHeader(HttpHeaders.CONTENT_TYPE, "application/json");
      response.setBody(
          Body.body(
              Buffer.buffer(
                  new JsonObject()
                      .put("error", "the upstream answered with a content encoding")
                      .encode())));
      return context.sendResponse();
    }
    scrubber.scrub(response.headers());
    Body body = response.getBody();
    if (body != null && carriesBody(context.request().getMethod(), response.getStatusCode())) {
      response.headers().remove(HttpHeaders.CONTENT_LENGTH);
      response.setBody(Body.body(new ScrubbingReadStream(body.stream(), scrubber), -1));
    }
    return context.sendResponse();
  }

  /** Whether an answer has a body to scrub: not to a HEAD, not 1xx, 204 or 304. */
  static boolean carriesBody(HttpMethod method, int status) {
    if (HttpMethod.HEAD.equals(method)) {
      return false;
    }
    return status >= 200 && status != 204 && status != 304;
  }

  @Override
  public String toString() {
    return "ResponseScrub";
  }
}
