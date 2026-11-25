package eu.wohlben.qits.egress.testdb;

import eu.wohlben.qits.servicemock.idp.MockIdp;
import java.util.Set;
import org.eclipse.microprofile.config.spi.ConfigSource;

/**
 * Points {@code qits.egress.idp.url} — the proxy listener's idp: discovery, JWKS and token
 * introspection — at this JVM's {@link SuiteIdp} (in front of its {@link MockIdp}), for every {@code
 * @QuarkusTest}. A config source
 * rather than a test profile, because the mock's port is chosen at run time and a profile would be
 * one more Quarkus application per surefire fork. The ordinal sits above application.properties
 * (250); it is registered through {@code META-INF/services}.
 *
 * <p>The management listener's OIDC tenant stays off in {@code %test}; only the proxy's own
 * validation dials the mock.
 */
public class MockIdpConfigSource implements ConfigSource {

  static final String KEY = "qits.egress.idp.url";

  @Override
  public int getOrdinal() {
    return 500;
  }

  @Override
  public Set<String> getPropertyNames() {
    return Set.of(KEY);
  }

  @Override
  public String getValue(String propertyName) {
    return KEY.equals(propertyName) ? SuiteIdp.ensureStarted() : null;
  }

  @Override
  public String getName() {
    return "egress-suite-mock-idp";
  }
}
