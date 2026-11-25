package eu.wohlben.qits.egress.testdb;

import eu.wohlben.qits.egress.support.SuiteTls;
import java.util.Set;
import org.eclipse.microprofile.config.spi.ConfigSource;

/**
 * Points {@code qits.egress.test.upstream-trust} at {@link SuiteTls#UPSTREAM}'s certificate for
 * every {@code @QuarkusTest}, so the upstream pools verify the suites' fake https third party — and
 * nothing the JVM trusts — the way they verify a real one. A config source, as {@link
 * MockIdpConfigSource} is, because the CA is made at run time; registered through {@code
 * META-INF/services}.
 */
public class SuiteTlsConfigSource implements ConfigSource {

  static final String KEY = "qits.egress.test.upstream-trust";

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
    return KEY.equals(propertyName) ? SuiteTls.ca(SuiteTls.UPSTREAM).pem().toString() : null;
  }

  @Override
  public String getName() {
    return "egress-suite-tls";
  }
}
