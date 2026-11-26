package eu.wohlben.qits.egress.api;

import eu.wohlben.qits.egress.claude.ClaudeCredentials;
import eu.wohlben.qits.egress.store.ClaudeCredentialStore;
import io.quarkus.security.identity.SecurityIdentity;
import jakarta.annotation.security.RolesAllowed;
import jakarta.inject.Inject;
import jakarta.ws.rs.Consumes;
import jakarta.ws.rs.GET;
import jakarta.ws.rs.PUT;
import jakarta.ws.rs.Path;
import jakarta.ws.rs.Produces;
import jakarta.ws.rs.QueryParam;
import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.Response;
import java.time.Instant;
import java.util.Arrays;
import java.util.List;
import java.util.Optional;
import org.eclipse.microprofile.openapi.annotations.Operation;
import org.eclipse.microprofile.openapi.annotations.responses.APIResponse;
import org.jboss.logging.Logger;

/**
 * {@code /egress/api/claude-credential}: the Claude subscription login this service holds for every
 * project's agents (epic qits-2525, qits-2664). The runner hands the node's login over and writes a
 * placeholder in its place; the proxy swaps the placeholder for the held access token on the Claude
 * hosts, and one replica refreshes the login before it expires.
 *
 * <ul>
 *   <li>{@code PUT ?mode=adopt|replace} — {@code qits:target-runner} only, body the {@code
 *       claudeAiOauth} object. {@code adopt} stores only when nothing is held: 204, or 409 {@code
 *       {"held":true}}. {@code replace} always stores (a fresh sign-in): 204. A placeholder token,
 *       a missing token or expiry, or another mode: 400.
 *   <li>{@code GET} — the status only, NEVER a token: {@code {held, expiresAt, refreshExpiresAt,
 *       scopes, subscriptionType, rateLimitTier, source, updatedAt, lastRefreshAt,
 *       lastRefreshError}}, {@code held} false and the rest null when none is held.
 * </ul>
 *
 * <p>No body this door writes ever carries a token: the refusals are fixed texts.
 */
@Path("/claude-credential")
@Produces(MediaType.APPLICATION_JSON)
public class ClaudeCredentialResource {

  private static final Logger LOG = Logger.getLogger(ClaudeCredentialResource.class);

  static final String ADOPT = "adopt";

  static final String REPLACE = "replace";

  @Inject SecurityIdentity identity;

  @Inject ClaudeCredentialStore store;

  @Inject ClaudeCredentials credentials;

  @PUT
  @Consumes(MediaType.APPLICATION_JSON)
  @RolesAllowed(Roles.TARGET_RUNNER)
  @Operation(
      operationId = "putClaudeCredential",
      summary = "Hand the Claude login over (adopt) or replace it after a sign-in (the runner only)")
  @APIResponse(responseCode = "204", description = "Stored")
  @APIResponse(
      responseCode = "400",
      description = "Not adopt or replace, a token or the expiry missing, or a placeholder")
  @APIResponse(responseCode = "403", description = "Not the runner")
  @APIResponse(responseCode = "409", description = "adopt, and a login is held already")
  public Response put(@QueryParam("mode") String mode, ClaudeCredentialWire.ClaudeAiOauth login) {
    if (!ADOPT.equals(mode) && !REPLACE.equals(mode)) {
      return refuse(Response.Status.BAD_REQUEST, "mode is adopt or replace");
    }
    String problem = problem(login);
    if (problem != null) {
      return refuse(Response.Status.BAD_REQUEST, problem);
    }
    String runner = identity.getPrincipal() == null ? "-" : identity.getPrincipal().getName();
    ClaudeCredentialStore.Login stored =
        new ClaudeCredentialStore.Login(
            login.accessToken(),
            login.refreshToken(),
            Instant.ofEpochMilli(login.expiresAt()),
            login.refreshTokenExpiresAt() == null
                ? null
                : Instant.ofEpochMilli(login.refreshTokenExpiresAt()),
            login.scopes() == null ? "" : String.join(" ", login.scopes()),
            login.subscriptionType(),
            login.rateLimitTier(),
            (ADOPT.equals(mode) ? "hand-over " : "sign-in ") + runner);
    if (ADOPT.equals(mode)) {
      if (!store.adopt(stored)) {
        return Response.status(Response.Status.CONFLICT)
            .entity(new ClaudeCredentialWire.Held(true))
            .build();
      }
    } else {
      store.replace(stored);
    }
    LOG.infof("the claude credential is stored (%s by %s)", mode, runner);
    // This replica swaps it in at once; the other reads it within qits.egress.claude.reread.
    credentials.reload();
    return Response.noContent().build();
  }

  @GET
  @RolesAllowed({Roles.AGENT, Roles.SYSTEM, Roles.ADMIN, Roles.TARGET_RUNNER})
  @Operation(
      operationId = "getClaudeCredential",
      summary = "Whether a Claude login is held, and its state — never a token")
  @APIResponse(responseCode = "200", description = "The status, held or not")
  public ClaudeCredentialWire.ClaudeCredentialStatus get() {
    Optional<ClaudeCredentialStore.Credential> held = store.held();
    if (held.isEmpty()) {
      return new ClaudeCredentialWire.ClaudeCredentialStatus(
          false, null, null, null, null, null, null, null, null, null);
    }
    ClaudeCredentialStore.Credential credential = held.get();
    return new ClaudeCredentialWire.ClaudeCredentialStatus(
        true,
        credential.expiresAt(),
        credential.refreshExpiresAt(),
        scopes(credential.scopes()),
        credential.subscriptionType(),
        credential.rateLimitTier(),
        credential.source(),
        credential.updatedAt(),
        credential.lastRefreshAt(),
        credential.lastRefreshError());
  }

  /** Why a body cannot be stored, as a fixed text that names no value; null when it can. */
  static String problem(ClaudeCredentialWire.ClaudeAiOauth login) {
    if (login == null) {
      return "the body is the claudeAiOauth object";
    }
    if (blank(login.accessToken()) || blank(login.refreshToken())) {
      return "accessToken and refreshToken are required";
    }
    if (ClaudeCredentials.PLACEHOLDER.equals(login.accessToken().trim())
        || ClaudeCredentials.PLACEHOLDER.equals(login.refreshToken().trim())) {
      return "the placeholder is not a login";
    }
    if (login.expiresAt() == null || login.expiresAt() <= 0) {
      return "expiresAt is required";
    }
    return null;
  }

  private static boolean blank(String value) {
    return value == null || value.isBlank();
  }

  private static List<String> scopes(String scopes) {
    return scopes == null || scopes.isBlank()
        ? List.of()
        : Arrays.stream(scopes.trim().split("\\s+")).toList();
  }

  private static Response refuse(Response.Status status, String message) {
    return Response.status(status).entity(new ClaudeCredentialWire.ErrorBody(message)).build();
  }
}
