package eu.wohlben.qits.egress.tls;

import eu.wohlben.qits.egress.support.SuiteWorkloads;
import io.vertx.core.net.KeyCertOptions;
import jakarta.inject.Singleton;
import java.security.cert.X509Certificate;
import javax.net.ssl.SSLContext;
import javax.net.ssl.X509TrustManager;

/**
 * The suites' {@link WorkloadTls} (qits-2759), standing in for qits-certificates' workload door and
 * the platform anchors in every {@code @QuarkusTest} ({@link TlsProxyWiring} takes a {@code
 * WorkloadTls} bean over the platform's): egress' own certificate, {@code application:qits-egress}
 * with DNS SANs {@code dev-qits-egress} and {@code localhost}, signed by {@link
 * SuiteWorkloads#ANCHOR}, the one CA 8082 trusts here.
 */
@Singleton
public class SuiteWorkloadTls implements WorkloadTls {

  private final SuiteWorkloads.Pair egress;

  public SuiteWorkloadTls() throws Exception {
    egress = SuiteWorkloads.application("qits-egress");
  }

  @Override
  public X509Certificate certificate() {
    return egress.certificate();
  }

  @Override
  public KeyCertOptions keyCertOptions() {
    try {
      return KeyCertOptions.wrap(egress.keyManager());
    } catch (Exception e) {
      throw new IllegalStateException(e);
    }
  }

  @Override
  public X509TrustManager clientTrust() {
    try {
      return SuiteWorkloads.trust(SuiteWorkloads.ANCHOR);
    } catch (Exception e) {
      throw new IllegalStateException(e);
    }
  }

  @Override
  public SSLContext clientContext() {
    try {
      return SuiteWorkloads.client(egress);
    } catch (Exception e) {
      throw new IllegalStateException(e);
    }
  }
}
