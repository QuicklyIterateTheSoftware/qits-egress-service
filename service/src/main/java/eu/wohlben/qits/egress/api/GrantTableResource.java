package eu.wohlben.qits.egress.api;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import eu.wohlben.qits.egress.grants.GrantIndex;
import eu.wohlben.qits.egress.store.GrantTableStore;
import io.quarkus.security.identity.SecurityIdentity;
import jakarta.annotation.security.RolesAllowed;
import jakarta.inject.Inject;
import jakarta.ws.rs.Consumes;
import jakarta.ws.rs.GET;
import jakarta.ws.rs.PUT;
import jakarta.ws.rs.Path;
import jakarta.ws.rs.Produces;
import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.Response;
import java.util.Set;
import org.eclipse.microprofile.openapi.annotations.Operation;
import org.eclipse.microprofile.openapi.annotations.responses.APIResponse;
import org.jboss.logging.Logger;

/**
 * {@code /egress/api/grant-table}: the grant table qits-deployments PUSHES (the 2026-11-25
 * correction of epic qits-2523: qits-deployments is private and this service public, so it cannot
 * pull). Stored in this service's own database, so both replicas read the one table the push stored
 * ({@link GrantIndex}).
 *
 * <ul>
 *   <li>{@code PUT} — the deployer's own client only ({@link GrantTablePublisher}). 204 when stored
 *       or when the version equals the held one (a repeated push is idempotent), 409 {@code
 *       {"error","held"}} when it is older, 400 when it has no version.
 *   <li>{@code GET} — {@code {version, receivedAt, routes, refused}}, or 404 when none is held. The
 *       deployer reads it back on each observation tick and pushes again when the version differs;
 *       people, the desk and agents read it for live checks.
 * </ul>
 */
@Path("/grant-table")
@Produces(MediaType.APPLICATION_JSON)
public class GrantTableResource {

  private static final Logger LOG = Logger.getLogger(GrantTableResource.class);

  static final String NOT_THE_PUBLISHER =
      "the grant table is pushed and read back by qits-deployments' own client only";

  /** The roles that read without being the publisher. */
  static final Set<String> READERS =
      Set.of(Roles.ADMIN, Roles.ADMIN_AGENT, Roles.DESK_ADMIN, Roles.AGENT);

  @Inject SecurityIdentity identity;

  @Inject GrantTablePublisher publisher;

  @Inject GrantTableStore store;

  @Inject GrantIndex index;

  @Inject ObjectMapper json;

  @PUT
  @Consumes(MediaType.APPLICATION_JSON)
  @RolesAllowed(Roles.SYSTEM)
  @Operation(
      operationId = "putGrantTable",
      summary = "Store the grant table in force (qits-deployments' own client only)")
  @APIResponse(responseCode = "204", description = "Stored, or the same version is already held")
  @APIResponse(responseCode = "400", description = "No table, or a table without a version")
  @APIResponse(responseCode = "403", description = "Not qits-deployments' own client")
  @APIResponse(responseCode = "409", description = "Older than the table held")
  public Response put(GrantTableWire.GrantTable table) {
    if (!publisher.is(identity)) {
      return Response.status(Response.Status.FORBIDDEN)
          .entity(new GrantTableWire.ErrorBody(NOT_THE_PUBLISHER))
          .build();
    }
    if (table == null || table.version() <= 0) {
      return Response.status(Response.Status.BAD_REQUEST)
          .entity(new GrantTableWire.ErrorBody("a grant table carries a positive version"))
          .build();
    }
    String body;
    try {
      body = json.writeValueAsString(table);
    } catch (JsonProcessingException e) {
      throw new IllegalStateException("the grant table does not serialise", e);
    }
    GrantTableStore.Stored stored = store.store(table.version(), body, publisher.principal());
    switch (stored.outcome()) {
      case STORED -> {
        LOG.infof(
            "grant table %d stored: %d routes, %d refused",
            table.version(), table.routes().size(), table.refused().size());
        // This replica serves it at once; the other picks it up on its next refresh.
        index.adopt(table);
        return Response.noContent().build();
      }
      case UNCHANGED -> {
        return Response.noContent().build();
      }
      default -> {
        return Response.status(Response.Status.CONFLICT)
            .entity(
                new GrantTableWire.OlderTable(
                    "the table is older than the one held", stored.held()))
            .build();
      }
    }
  }

  @GET
  @RolesAllowed({Roles.SYSTEM, Roles.ADMIN, Roles.ADMIN_AGENT, Roles.DESK_ADMIN, Roles.AGENT})
  @Operation(operationId = "getGrantTable", summary = "The grant table held, and when it arrived")
  @APIResponse(responseCode = "200", description = "The table held")
  @APIResponse(responseCode = "403", description = "A service other than qits-deployments")
  @APIResponse(responseCode = "404", description = "No table was pushed yet")
  public Response get() {
    boolean reader = READERS.stream().anyMatch(identity::hasRole);
    if (!reader && !publisher.is(identity)) {
      return Response.status(Response.Status.FORBIDDEN)
          .entity(new GrantTableWire.ErrorBody(NOT_THE_PUBLISHER))
          .build();
    }
    return store
        .held()
        .map(
            held -> {
              GrantTableWire.GrantTable table = index.parse(held.body());
              return Response.ok(
                      new GrantTableWire.HeldTable(
                          held.version(), held.receivedAt(), table.routes(), table.refused()))
                  .build();
            })
        .orElseGet(
            () ->
                Response.status(Response.Status.NOT_FOUND)
                    .entity(new GrantTableWire.ErrorBody("no grant table is held"))
                    .build());
  }
}
