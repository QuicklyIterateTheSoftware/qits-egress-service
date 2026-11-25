package eu.wohlben.qits.egress.identity;

import io.vertx.core.Future;
import io.vertx.core.Vertx;
import io.vertx.core.http.HttpClientOptions;
import jakarta.annotation.PostConstruct;
import jakarta.enterprise.context.ApplicationScoped;
import jakarta.inject.Inject;
import java.time.Duration;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Optional;
import org.eclipse.microprofile.config.inject.ConfigProperty;
import org.jboss.logging.Logger;

/**
 * <b>The bearer a platform route's target receives</b>: the caller's own, exchanged at qits-idp
 * ({@link IdpTokenExchange}) for a JWT whose {@code sub} — and groups, project, agent… — are the
 * caller's and whose {@code act.sub} is this service's client, {@code
 * ${QITS_ENVIRONMENT}-qits-egress}. The target sees who called, and that the call came through the
 * gateway; the exchange never widens access.
 *
 * <p><b>Cached per caller token</b>, keyed by its SHA-256 (never the token), until {@value
 * #EARLY_SECONDS} s before the exchanged token expires; a token with less life than that is not
 * cached. Bounded like the introspection cache. A refusal is not cached: it costs idp one request,
 * and a caller whose next token is good should not wait out a window.
 *
 * <p>The exchanged bearer goes to the platform route's target and nowhere else — {@code
 * proxy/PlatformOutbound} refuses a route that is not a platform route.
 */
@ApplicationScoped
public class PlatformBearers {

  private static final Logger LOG = Logger.getLogger(PlatformBearers.class);

  /** How long before its expiry an exchanged token stops being handed out. */
  static final long EARLY_SECONDS = 30;

  static final int CACHE_SIZE = 4096;

  /**
   * The verdict about one exchange.
   *
   * @param bearer the exchanged JWT; null when refused
   * @param status 502 (idp refused) or 503 (idp unreachable) when refused
   * @param reason the audit line's reason when refused
   */
  public record Verdict(String bearer, int status, String reason) {

    public boolean exchanged() {
      return bearer != null;
    }
  }

  private record Held(String bearer, long untilMillis) {}

  @Inject Vertx vertx;

  @ConfigProperty(name = "qits.egress.idp.url")
  String idpUrl;

  @ConfigProperty(name = "qits.egress.idp.client-id")
  String clientId;

  @ConfigProperty(name = "qits.egress.idp.client-secret")
  Optional<String> clientSecret;

  @ConfigProperty(name = "qits.egress.idp.timeout", defaultValue = "5s")
  Duration timeout;

  private IdpTokenExchange exchange;

  private Map<String, Held> held;

  @PostConstruct
  void open() {
    exchange =
        new IdpTokenExchange(
            vertx.createHttpClient(new HttpClientOptions().setKeepAlive(true)),
            idpUrl,
            clientId,
            clientSecret.orElse(null),
            timeout.toMillis());
    held =
        Collections.synchronizedMap(
            new LinkedHashMap<>(16, 0.75f, true) {
              @Override
              protected boolean removeEldestEntry(Map.Entry<String, Held> eldest) {
                return size() > CACHE_SIZE;
              }
            });
  }

  /**
   * The exchanged bearer for one caller's raw bearer. Never a failed future: idp's refusal is a 502
   * verdict, an unreachable idp a 503.
   */
  public Future<Verdict> bearerFor(String callerBearer) {
    String key = CallerIdentity.fingerprint(callerBearer);
    Held known = held.get(key);
    if (known != null) {
      if (known.untilMillis() > System.currentTimeMillis()) {
        return Future.succeededFuture(new Verdict(known.bearer(), 0, null));
      }
      held.remove(key, known);
    }
    if (!exchange.hasCredential()) {
      LOG.warn("no idp client secret (QITS_RESOURCE_IDP_CLIENT_SECRET): no platform route can be served");
      return Future.succeededFuture(refused());
    }
    return exchange
        .exchange(callerBearer)
        .map(
            answer -> {
              if (answer.status() != 200) {
                LOG.warnf("qits-idp refused a token exchange: %d", answer.status());
                return refused();
              }
              IdpTokenExchange.Exchanged exchanged;
              try {
                exchanged = IdpTokenExchange.Exchanged.of(answer.body());
              } catch (RuntimeException unreadable) {
                return refused();
              }
              if (exchanged.accessToken() == null || exchanged.accessToken().isBlank()) {
                return refused();
              }
              long life = exchanged.expiresIn() - EARLY_SECONDS;
              if (life > 0) {
                held.put(
                    key,
                    new Held(exchanged.accessToken(), System.currentTimeMillis() + life * 1000));
              }
              return new Verdict(exchanged.accessToken(), 0, null);
            })
        .recover(
            failure -> {
              LOG.warnf("could not reach qits-idp for a token exchange: %s", failure.toString());
              return Future.succeededFuture(new Verdict(null, 503, "idp-unreachable"));
            });
  }

  private static Verdict refused() {
    return new Verdict(null, 502, "exchange-refused");
  }

  @Override
  public String toString() {
    return "PlatformBearers";
  }
}
