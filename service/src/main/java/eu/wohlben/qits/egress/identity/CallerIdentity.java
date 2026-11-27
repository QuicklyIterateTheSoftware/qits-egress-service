package eu.wohlben.qits.egress.identity;

import io.vertx.core.Future;
import io.vertx.core.Vertx;
import io.vertx.core.http.HttpClientOptions;
import jakarta.annotation.PostConstruct;
import jakarta.enterprise.context.ApplicationScoped;
import jakarta.inject.Inject;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.time.Duration;
import java.time.Instant;
import java.util.Base64;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Optional;
import org.eclipse.microprofile.config.inject.ConfigProperty;
import org.jboss.logging.Logger;

/**
 * <b>Who is calling the proxy listener</b>, from its {@code Authorization: Bearer …} — qits-edge's
 * {@code EdgeAuth} bearer and token paths, reduced to what the gateway needs:
 *
 * <ul>
 *   <li><b>A JWT</b> is validated offline: RS256, a {@code kid} the idp's JWKS publishes, the
 *       issuer the idp's discovery names, not expired, and {@code aud} holding {@code
 *       qits-platform}. Claims are checked before the signature, so an expired or misaddressed token
 *       costs no key lookup and a made-up kid cannot force one.
 *   <li><b>An opaque {@code qits_tok_…}</b> is introspected at idp with this service's own client
 *       ({@link IdpIntrospection}), and the JWT it stands for is held to the same rules. idp's
 *       answer is cached against a SHA-256 of the token — never the token — for {@code
 *       qits.egress.idp.token-cache-ttl} (15 s), refusals included, and never past the minted JWT's
 *       own life. A revoked token is believed for at most that window.
 * </ul>
 *
 * <p>The validated claims become a {@link Principal}. A missing or bad credential is a 401; an idp
 * that cannot be reached is a 503 and is never cached: nothing was learnt about the caller.
 */
@ApplicationScoped
public class CallerIdentity {

  private static final Logger LOG = Logger.getLogger(CallerIdentity.class);

  /** The one audience every platform token carries. */
  static final String PLATFORM_AUDIENCE = "qits-platform";

  /** The prefix idp puts on every opaque token it issues. */
  static final String TOKEN_PREFIX = "qits_tok_";

  private static final String BEARER = "bearer ";

  /** Bounded, since every made-up token is an entry. */
  static final int TOKEN_CACHE_SIZE = 4096;

  /**
   * The verdict about one credential.
   *
   * @param principal who is calling; null when refused
   * @param status 401 or 503 when refused
   * @param reason the audit line's reason when refused
   * @param message the refusal's text for the caller — never the credential
   */
  public record Verdict(Principal principal, int status, String reason, String message) {

    public static Verdict of(Principal principal) {
      return new Verdict(principal, 0, null, null);
    }

    public static Verdict refused(int status, String reason, String message) {
      return new Verdict(null, status, reason, message);
    }

    public boolean admitted() {
      return principal != null;
    }
  }

  /** One cached introspection: the verdict and until when it is believed. */
  private record Believed(Verdict verdict, long untilMillis) {}

  @Inject Vertx vertx;

  @ConfigProperty(name = "qits.egress.idp.url")
  String idpUrl;

  @ConfigProperty(name = "qits.egress.idp.client-id")
  String clientId;

  @ConfigProperty(name = "qits.egress.idp.client-secret")
  Optional<String> clientSecret;

  @ConfigProperty(name = "qits.egress.idp.timeout", defaultValue = "5s")
  Duration timeout;

  @ConfigProperty(name = "qits.egress.idp.token-cache-ttl", defaultValue = "15s")
  Duration tokenCacheTtl;

  @ConfigProperty(name = "qits.egress.idp.jwks-refresh-cooldown", defaultValue = "10s")
  Duration jwksRefreshCooldown;

  @ConfigProperty(name = "qits.egress.idp.clock-skew", defaultValue = "30s")
  Duration clockSkew;

  @ConfigProperty(name = "qits.egress.environment")
  String environment;

  private IdpKeys keys;

  private IdpIntrospection introspection;

  private Map<String, Believed> tokens;

  @PostConstruct
  void open() {
    // Its own small client: idp calls are short JSON reads that must fail fast, the opposite of the
    // proxy client's long-lived streams.
    var client = vertx.createHttpClient(new HttpClientOptions().setKeepAlive(true));
    keys = new IdpKeys(client, idpUrl, timeout.toMillis(), jwksRefreshCooldown.toMillis());
    introspection =
        new IdpIntrospection(
            client, idpUrl, clientId, clientSecret.orElse(null), timeout.toMillis());
    tokens =
        Collections.synchronizedMap(
            new LinkedHashMap<>(16, 0.75f, true) {
              @Override
              protected boolean removeEldestEntry(Map.Entry<String, Believed> eldest) {
                return size() > TOKEN_CACHE_SIZE;
              }
            });
    if (!introspection.hasCredential()) {
      LOG.warn(
          "no idp client secret (QITS_RESOURCE_IDP_CLIENT_SECRET): every opaque qits_tok_ caller"
              + " of the proxy is refused; JWT callers are unaffected");
    }
  }

  /**
   * The verdict about one {@code Authorization} header. Never a failed future: an unreachable idp
   * is a 503 verdict.
   */
  public Future<Verdict> identify(String authorization) {
    if (authorization == null || !authorization.toLowerCase(Locale.ROOT).startsWith(BEARER)) {
      return Future.succeededFuture(
          Verdict.refused(401, "no-credentials", "a bearer token is required"));
    }
    String presented = authorization.substring(BEARER.length()).trim();
    Future<Verdict> verdict =
        presented.startsWith(TOKEN_PREFIX) ? token(presented) : jwt(presented);
    return verdict.recover(
        failure -> {
          LOG.warnf("could not ask qits-idp about a caller: %s", failure.toString());
          return Future.succeededFuture(
              Verdict.refused(503, "idp-unreachable", "the identity provider cannot be reached"));
        });
  }

  /** Validate a JWT offline. A failed future only when idp could not be reached. */
  Future<Verdict> jwt(String compact) {
    SignedJwt jwt;
    try {
      jwt = SignedJwt.parse(compact);
    } catch (IllegalArgumentException e) {
      return Future.succeededFuture(bad(e.getMessage()));
    }
    return keys.issuer()
        .compose(
            issuer -> {
              String problem =
                  jwt.problem(
                      List.of(issuer), PLATFORM_AUDIENCE, Instant.now(), clockSkew.toSeconds());
              if (problem != null) {
                return Future.succeededFuture(bad(problem));
              }
              return keys.find(jwt.kid())
                  .map(
                      key ->
                          jwt.signatureMatches(key)
                              ? Verdict.of(Principal.of(jwt.claims(), environment))
                              : bad("the token's signature does not verify"))
                  .recover(
                      failure ->
                          failure instanceof IdpKeys.UnknownKey
                              ? Future.succeededFuture(bad(failure.getMessage()))
                              : Future.failedFuture(failure));
            });
  }

  /** Introspect an opaque token, cached. A failed future only when idp could not be reached. */
  Future<Verdict> token(String token) {
    String fingerprint = fingerprint(token);
    Believed known = tokens.get(fingerprint);
    long now = System.currentTimeMillis();
    if (known != null) {
      if (known.untilMillis() > now) {
        return Future.succeededFuture(known.verdict());
      }
      tokens.remove(fingerprint, known);
    }
    if (!introspection.hasCredential()) {
      return Future.succeededFuture(bad("this gateway cannot introspect tokens"));
    }
    return introspection
        .introspect(token)
        .compose(
            answer -> {
              if (answer.status() != 200) {
                // idp DECIDED: believed for the same window a yes is.
                Verdict refused = bad("the identity provider refused this token");
                tokens.put(
                    fingerprint,
                    new Believed(refused, System.currentTimeMillis() + tokenCacheTtl.toMillis()));
                return Future.succeededFuture(refused);
              }
              IdpIntrospection.Introspected minted;
              try {
                minted = IdpIntrospection.Introspected.of(answer.body());
              } catch (RuntimeException e) {
                return Future.succeededFuture(bad("the identity provider issued no usable token"));
              }
              if (minted.accessToken() == null) {
                return Future.succeededFuture(bad("the identity provider issued no usable token"));
              }
              return jwt(minted.accessToken())
                  .map(
                      verdict -> {
                        if (verdict.admitted()) {
                          long at = System.currentTimeMillis();
                          long until =
                              Math.min(
                                  at + tokenCacheTtl.toMillis(),
                                  at + Math.max(0, minted.expiresIn()) * 1000);
                          tokens.put(fingerprint, new Believed(verdict, until));
                        }
                        // A minted JWT that does not hold up here is a fault between the two
                        // processes, not a verdict about the token: not cached.
                        return verdict;
                      });
            });
  }

  private static Verdict bad(String message) {
    return Verdict.refused(401, "bad-credentials", message);
  }

  /** A credential as a cache key: SHA-256, so the token is never a map key or a log line. */
  static String fingerprint(String credential) {
    try {
      return Base64.getUrlEncoder()
          .withoutPadding()
          .encodeToString(
              MessageDigest.getInstance("SHA-256")
                  .digest(credential.getBytes(StandardCharsets.UTF_8)));
    } catch (NoSuchAlgorithmException e) {
      throw new IllegalStateException("SHA-256 is not usable in this JVM", e);
    }
  }
}
