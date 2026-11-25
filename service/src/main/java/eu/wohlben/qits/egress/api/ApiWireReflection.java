package eu.wohlben.qits.egress.api;

import io.quarkus.runtime.annotations.RegisterForReflection;

/**
 * Native-image reflection registration for every type Jackson touches on the grant-table door —
 * and on the replicas' read of the stored table, which binds the same records outside any REST
 * method, where the build-time analysis cannot see them. Several ride in {@code
 * Response.entity(...)}, which hides the type too: in the native binary that is a 500 behind a green
 * JVM suite.
 *
 * <p><b>A new wire type joins this list in the commit that adds it</b>; ApiWireReflectionTest fails
 * naming any nested type of {@link GrantTableWire} left out.
 */
@RegisterForReflection(
    targets = {
      GrantTableWire.GrantTable.class,
      GrantTableWire.Route.class,
      GrantTableWire.Refused.class,
      GrantTableWire.HeldTable.class,
      GrantTableWire.ErrorBody.class,
      GrantTableWire.OlderTable.class
    })
public final class ApiWireReflection {

  private ApiWireReflection() {}
}
