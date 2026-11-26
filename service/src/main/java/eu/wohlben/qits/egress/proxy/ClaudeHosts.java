package eu.wohlben.qits.egress.proxy;

import eu.wohlben.qits.egress.claude.ClaudeCredentials;
import eu.wohlben.qits.egress.identity.Principal;
import io.vertx.core.buffer.Buffer;
import io.vertx.core.http.HttpMethod;
import io.vertx.core.http.RequestOptions;
import io.vertx.core.json.DecodeException;
import io.vertx.core.json.JsonObject;
import io.vertx.core.net.HostAndPort;
import jakarta.annotation.PostConstruct;
import jakarta.enterprise.context.ApplicationScoped;
import jakarta.enterprise.inject.Instance;
import jakarta.inject.Inject;
import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.util.Collections;
import java.util.List;
import java.util.Locale;
import java.util.Set;
import java.util.TreeSet;
import org.eclipse.microprofile.config.inject.ConfigProperty;

/**
 * <b>The Claude hosts</b> (epic qits-2525, qits-2664): {@code qits.egress.claude.hosts}
 * ({@code api.anthropic.com,platform.claude.com,claude.ai}), where a principal with a project — a
 * {@code project:}, or an {@code agent:} carrying its project; never an application — reaches
 * Claude with the login this service holds ({@link ClaudeCredentials}) while its container holds
 * only a placeholder.
 *
 * <ul>
 *   <li>{@code CONNECT <host>:443} is INTERCEPTED (a leaf of ours, {@code tls=intercepted}) even
 *       without a route, after the granted routes and before the passthrough — but only while a
 *       login is held ({@link ClaudeCredentials#current()}, decided per CONNECT). With none held the
 *       host is like any other: the passthrough's blind splice, so a container without the
 *       platform's anchor in its trust store keeps working until the hand-over.
 *   <li>{@code Authorization: Bearer qits-egress-placeholder} → {@code Bearer <held access token>};
 *       any other {@code Authorization} is forwarded unchanged ({@link ClaudeOutbound}).
 *   <li>{@code POST /v1/oauth/token} on {@value #TOKEN_HOST} whose JSON or form body carries {@code
 *       refresh_token=qits-egress-placeholder} is answered here ({@link #placeholderRefresh}): the
 *       refresh Claude Code sends after a 401, which would otherwise blank its credentials file.
 *   <li>The held tokens are scrubbed out of every answer ({@link Scrubber}), streamed; WebSocket
 *       upgrades take the same swap.
 *   <li>Nothing held any more inside a tunnel intercepted while one was: a placeholder request is
 *       503 {@code {"error":"no claude credential held"}}.
 *   <li>Audit {@code route=claude}.
 * </ul>
 */
@ApplicationScoped
public class ClaudeHosts {

  /** The audit line's route name. */
  static final String ROUTE = "claude";

  /** The only port a Claude host is intercepted on. */
  static final int PORT = 443;

  /** Where Claude Code refreshes its login. */
  static final String TOKEN_HOST = "platform.claude.com";

  static final String TOKEN_PATH = "/v1/oauth/token";

  /** The largest token request read whole to look for the placeholder. */
  static final int TOKEN_BODY_LIMIT = 64 * 1024;

  /** The synthetic answer's lifetime: a year, so Claude Code does not ask again soon. */
  static final long PLACEHOLDER_EXPIRES_IN = 31_536_000L;

  static final String PLACEHOLDER_BEARER = "Bearer " + ClaudeCredentials.PLACEHOLDER;

  @ConfigProperty(
      name = "qits.egress.claude.hosts",
      defaultValue = "api.anthropic.com,platform.claude.com,claude.ai")
  List<String> configured;

  /**
   * A {@link ClaudeUpstream} bean, when there is one: the suites' loopback dial. A deployment has
   * none, and the host is dialled on 443.
   */
  @Inject Instance<ClaudeUpstream> upstreams;

  private Set<String> hosts = Set.of();

  private ClaudeUpstream upstream = ClaudeUpstream.SYSTEM;

  @PostConstruct
  void build() {
    TreeSet<String> names = new TreeSet<>();
    for (String host : configured) {
      if (host != null && !host.isBlank()) {
        names.add(host.trim().toLowerCase(Locale.ROOT));
      }
    }
    hosts = Collections.unmodifiableSortedSet(names);
    if (upstreams.isResolvable()) {
      upstream = upstreams.get();
    }
  }

  /** The Claude hosts, lower case: the leaves wanted for them too. */
  public Set<String> hosts() {
    return hosts;
  }

  /** Whether {@code principal} gets the Claude behaviour for {@code host:port}. */
  boolean serves(Principal principal, String host, int port) {
    return principal != null
        && principal.application() == null
        && principal.project() != null
        && port == PORT
        && host != null
        && hosts.contains(host.toLowerCase(Locale.ROOT));
  }

  /** Where {@code host}'s requests are dialled: TLS, the acquisition bound. */
  RequestOptions origin(String host) {
    HostAndPort dial = upstream.dial(host);
    return new RequestOptions()
        .setHost(dial.host())
        .setPort(dial.port())
        .setSsl(true)
        .setConnectTimeout(ProxyClients.ACQUIRE_TIMEOUT_MS);
  }

  /** Whether {@code authorization} is the placeholder bearer (the scheme in any case). */
  static boolean isPlaceholder(String authorization) {
    if (authorization == null) {
      return false;
    }
    String value = authorization.trim();
    return value.regionMatches(true, 0, "Bearer ", 0, 7)
        && value.substring(7).trim().equals(ClaudeCredentials.PLACEHOLDER);
  }

  /** Whether a request is Claude Code's token refresh, whose body is read to tell. */
  static boolean isTokenRequest(HttpMethod method, String host, String path) {
    return HttpMethod.POST.equals(method)
        && TOKEN_HOST.equalsIgnoreCase(host)
        && TOKEN_PATH.equals(path);
  }

  /**
   * Whether a token request's body refreshes the placeholder: a JSON object whose {@code
   * refresh_token} is it, or a form whose {@code refresh_token} field is.
   */
  static boolean placeholderRefresh(String contentType, Buffer body) {
    if (body == null || body.length() == 0) {
      return false;
    }
    String text = body.toString(StandardCharsets.UTF_8).trim();
    boolean json =
        text.startsWith("{")
            || (contentType != null && contentType.toLowerCase(Locale.ROOT).contains("json"));
    if (json) {
      try {
        return ClaudeCredentials.PLACEHOLDER.equals(new JsonObject(text).getValue("refresh_token"));
      } catch (DecodeException | ClassCastException e) {
        return false;
      }
    }
    for (String field : text.split("&")) {
      int equals = field.indexOf('=');
      if (equals <= 0) {
        continue;
      }
      try {
        String name = URLDecoder.decode(field.substring(0, equals), StandardCharsets.UTF_8);
        String value = URLDecoder.decode(field.substring(equals + 1), StandardCharsets.UTF_8);
        if (name.equals("refresh_token") && value.equals(ClaudeCredentials.PLACEHOLDER)) {
          return true;
        }
      } catch (IllegalArgumentException e) {
        return false;
      }
    }
    return false;
  }

  /** The answer to a placeholder refresh: the placeholder again, with the held scopes. */
  static JsonObject placeholderToken(String scopes) {
    return new JsonObject()
        .put("token_type", "Bearer")
        .put("access_token", ClaudeCredentials.PLACEHOLDER)
        .put("refresh_token", ClaudeCredentials.PLACEHOLDER)
        .put("expires_in", PLACEHOLDER_EXPIRES_IN)
        .put("scope", scopes == null ? "" : scopes);
  }
}
