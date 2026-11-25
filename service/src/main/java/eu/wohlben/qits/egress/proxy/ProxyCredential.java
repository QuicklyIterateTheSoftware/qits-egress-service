package eu.wohlben.qits.egress.proxy;

import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.Locale;

/**
 * <b>The caller's bearer from {@code Proxy-Authorization}</b>, the header an {@code HTTP(S)_PROXY}
 * client sends: {@code Basic base64(<any user>:<bearer>)} — what {@code curl -U}, the JDK and most
 * clients send from a proxy URL's {@code user:password} — or {@code Bearer <bearer>}. The user name
 * is ignored; the password is the bearer.
 */
final class ProxyCredential {

  private ProxyCredential() {}

  /**
   * The header as an {@code Authorization: Bearer} value {@link
   * eu.wohlben.qits.egress.identity.CallerIdentity} takes, or null when there is none to take — the
   * caller is then answered 407.
   */
  static String bearer(String proxyAuthorization) {
    if (proxyAuthorization == null) {
      return null;
    }
    String value = proxyAuthorization.trim();
    String lower = value.toLowerCase(Locale.ROOT);
    if (lower.startsWith("bearer ")) {
      String token = value.substring("bearer ".length()).trim();
      return token.isEmpty() ? null : "Bearer " + token;
    }
    if (lower.startsWith("basic ")) {
      String decoded;
      try {
        decoded =
            new String(
                Base64.getDecoder().decode(value.substring("basic ".length()).trim()),
                StandardCharsets.UTF_8);
      } catch (IllegalArgumentException notBase64) {
        return null;
      }
      int colon = decoded.indexOf(':');
      String token = colon < 0 ? "" : decoded.substring(colon + 1).trim();
      return token.isEmpty() ? null : "Bearer " + token;
    }
    return null;
  }
}
