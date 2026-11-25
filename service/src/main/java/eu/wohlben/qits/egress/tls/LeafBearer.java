package eu.wohlben.qits.egress.tls;

import io.quarkus.oidc.client.NamedOidcClient;
import io.quarkus.oidc.client.OidcClient;
import io.quarkus.oidc.client.runtime.TokensHelper;
import jakarta.enterprise.context.ApplicationScoped;
import jakarta.inject.Inject;
import java.util.Optional;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.CompletionStage;
import org.eclipse.microprofile.config.inject.ConfigProperty;

/**
 * The bearer a leaf request presents: this service's own {@code qits:system} token, minted by the
 * named oidc client {@code qits} (the {@code idp:client} resource, id {@code <env>-qits-egress} —
 * the requester qits-certificates admits). The mint is cached and refreshed by {@link
 * TokensHelper}, as qits-artifacts' {@code QitsClientBearer} does.
 *
 * <p>Off (the extension's own {@code quarkus.oidc-client.qits.client-enabled}, false under %dev and
 * %test) it answers empty without dialling anything, and no leaf is asked for. Never blocks: the
 * stage completes when idp answers.
 */
@ApplicationScoped
public class LeafBearer {

  @Inject
  @NamedOidcClient("qits")
  OidcClient qits;

  @ConfigProperty(name = "quarkus.oidc-client.qits.client-enabled", defaultValue = "false")
  boolean enabled;

  private final TokensHelper helper = new TokensHelper();

  /** The access token, or empty when this process holds no client. */
  public CompletionStage<Optional<String>> token() {
    if (!enabled) {
      return CompletableFuture.completedFuture(Optional.empty());
    }
    return helper
        .getTokens(qits)
        .map(tokens -> Optional.ofNullable(tokens.getAccessToken()).filter(t -> !t.isBlank()))
        .subscribeAsCompletionStage();
  }
}
