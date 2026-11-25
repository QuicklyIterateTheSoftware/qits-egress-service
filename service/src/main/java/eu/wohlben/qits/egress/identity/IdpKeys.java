package eu.wohlben.qits.egress.identity;

import io.vertx.core.Future;
import io.vertx.core.http.HttpClient;
import io.vertx.core.http.HttpClientRequest;
import io.vertx.core.http.HttpMethod;
import io.vertx.core.http.RequestOptions;
import io.vertx.core.json.JsonArray;
import io.vertx.core.json.JsonObject;
import java.math.BigInteger;
import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.RSAPublicKeySpec;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.Map;
import org.jboss.logging.Logger;

/**
 * qits-idp's issuer and public signing keys, cached here and refreshed when a token names a key
 * this process has not seen — qits-edge's {@code IdpKeys}, adapted.
 *
 * <p><b>Offline validation is the design</b>: the proxy listener validates every presented JWT by
 * arithmetic against these keys, so idp is on no request's path but the rare one that meets a new
 * {@code kid}.
 *
 * <p><b>The issuer and the key set's address come from discovery</b> — {@code issuer} and {@code
 * jwks_uri} of {@code <idp>/.well-known/openid-configuration}, the same idp ({@code
 * qits.egress.idp.url}) and the same document this service's own quarkus-oidc tenant validates
 * against, so the gateway accepts exactly the tokens the management door does. Read once and kept
 * until a key fetch fails.
 *
 * <p><b>An unknown kid buys ONE fetch, behind a cooldown</b>, so a made-up {@code kid} cannot drive
 * one request per request at the identity provider; a burst of them shares the one fetch in flight.
 */
public final class IdpKeys {

  private static final Logger LOG = Logger.getLogger(IdpKeys.class);

  /** What discovery said: the issuer to accept and where the keys are. */
  record Discovery(String issuer, String jwksUri) {}

  private final HttpClient client;

  private final String idpUrl;

  private final long timeoutMs;

  private final long cooldownMs;

  /** kid to key. Replaced whole on every successful fetch, never mutated. */
  private volatile Map<String, RSAPublicKey> keys = Map.of();

  private volatile long lastFetchMillis;

  /** The discovery document's facts; null until read, and again after a failed fetch. */
  private volatile Discovery discovery;

  /** The fetch in progress, so a burst of unknown-kid requests makes one request, not a burst. */
  private Future<Map<String, RSAPublicKey>> inFlight;

  /**
   * @param client a small client of its own, never the proxy's
   * @param idpUrl the idp's base, ending in {@code /idp}
   * @param timeoutMs the bound on each call, connection included
   * @param cooldownMs how long after a fetch an unknown kid waits for the next one
   */
  public IdpKeys(HttpClient client, String idpUrl, long timeoutMs, long cooldownMs) {
    this.client = client;
    this.idpUrl = trimmed(idpUrl);
    this.timeoutMs = timeoutMs;
    this.cooldownMs = cooldownMs;
  }

  /** The issuer an accepted token carries: the discovery document's {@code issuer}. */
  public Future<String> issuer() {
    return discover().map(Discovery::issuer);
  }

  /**
   * The key that signed a token, or a failed future when there is none.
   *
   * @param kid the token's {@code kid} header
   */
  public Future<RSAPublicKey> find(String kid) {
    RSAPublicKey known = keys.get(kid);
    if (known != null) {
      return Future.succeededFuture(known);
    }
    return refresh()
        .compose(
            fetched -> {
              RSAPublicKey key = fetched.get(kid);
              return key != null
                  ? Future.succeededFuture(key)
                  : Future.failedFuture(new UnknownKey(kid));
            });
  }

  /** A kid the published set does not hold: a verdict about the token, not an idp outage. */
  public static final class UnknownKey extends RuntimeException {
    UnknownKey(String kid) {
      super("no published key with kid " + kid, null, false, false);
    }
  }

  private synchronized Future<Map<String, RSAPublicKey>> refresh() {
    if (inFlight != null) {
      return inFlight;
    }
    if (System.currentTimeMillis() - lastFetchMillis < cooldownMs) {
      return Future.succeededFuture(keys);
    }
    Future<Map<String, RSAPublicKey>> fetch =
        discover().compose(found -> get(found.jwksUri())).map(body -> parse(new JsonObject(body)));
    inFlight = fetch;
    fetch.onComplete(
        result -> {
          synchronized (this) {
            inFlight = null;
            lastFetchMillis = System.currentTimeMillis();
          }
          if (result.succeeded()) {
            keys = result.result();
            LOG.infof("read %d signing keys from %s", keys.size(), idpUrl);
          } else {
            // Discover again next time: a moved key set must not strand this process on the old
            // address.
            discovery = null;
            LOG.errorf(result.cause(), "could not read the signing keys of %s", idpUrl);
          }
        });
    return fetch;
  }

  private Future<Discovery> discover() {
    Discovery known = discovery;
    if (known != null) {
      return Future.succeededFuture(known);
    }
    return get(idpUrl + "/.well-known/openid-configuration")
        .map(
            body -> {
              Discovery found = discovered(new JsonObject(body));
              discovery = found;
              return found;
            });
  }

  /** The issuer and {@code jwks_uri} of a discovery document. */
  static Discovery discovered(JsonObject document) {
    String uri = document.getString("jwks_uri");
    String issuer = document.getString("issuer");
    if (uri == null || uri.isBlank() || issuer == null || issuer.isBlank()) {
      throw new IllegalArgumentException("idp's discovery document names no issuer or jwks_uri");
    }
    return new Discovery(issuer, uri);
  }

  private Future<String> get(String uri) {
    RequestOptions options =
        new RequestOptions()
            .setMethod(HttpMethod.GET)
            .setAbsoluteURI(uri)
            // BOUNDED: a fetch is shared by every request that met an unknown kid, so an idp that
            // accepts the connection and never answers would otherwise wedge this cache.
            .setConnectTimeout(timeoutMs)
            .setTimeout(timeoutMs);
    return client
        .request(options)
        .compose(HttpClientRequest::send)
        .compose(
            response ->
                response.statusCode() == 200
                    ? response.body().map(Object::toString)
                    : Future.failedFuture(uri + " answered " + response.statusCode()));
  }

  /**
   * A JWKS document to usable keys: RSA keys with a {@code kid} only — anything else is a key this
   * process could not verify with anyway.
   */
  static Map<String, RSAPublicKey> parse(JsonObject document) {
    Map<String, RSAPublicKey> parsed = new LinkedHashMap<>();
    JsonArray found = document.getJsonArray("keys");
    if (found == null) {
      throw new IllegalArgumentException("a JWKS document has a `keys` array");
    }
    for (int i = 0; i < found.size(); i++) {
      JsonObject jwk = found.getJsonObject(i);
      String kid = jwk.getString("kid");
      if (kid == null || !"RSA".equals(jwk.getString("kty"))) {
        continue;
      }
      parsed.put(kid, rsa(jwk.getString("n"), jwk.getString("e")));
    }
    return Map.copyOf(parsed);
  }

  private static RSAPublicKey rsa(String modulus, String exponent) {
    try {
      // Sign 1: these are UNSIGNED big-endian values.
      RSAPublicKeySpec spec =
          new RSAPublicKeySpec(
              new BigInteger(1, Base64.getUrlDecoder().decode(modulus)),
              new BigInteger(1, Base64.getUrlDecoder().decode(exponent)));
      return (RSAPublicKey) KeyFactory.getInstance("RSA").generatePublic(spec);
    } catch (GeneralSecurityException | RuntimeException e) {
      throw new IllegalArgumentException("a published key is not a usable RSA key", e);
    }
  }

  static String trimmed(String value) {
    String url = value.trim();
    while (url.endsWith("/")) {
      url = url.substring(0, url.length() - 1);
    }
    return url;
  }
}
