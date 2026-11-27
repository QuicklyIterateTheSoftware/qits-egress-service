package eu.wohlben.qits.egress.tls;

import eu.wohlben.qits.trust.PlatformTrust;
import eu.wohlben.qits.trust.WorkloadCertificate;
import io.vertx.core.net.KeyCertOptions;
import java.security.GeneralSecurityException;
import java.security.cert.X509Certificate;
import javax.net.ssl.KeyManager;
import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManager;
import javax.net.ssl.X509TrustManager;

/**
 * The deployment's {@link WorkloadTls}: qits-trust-core's {@link WorkloadCertificate} (opted in by
 * {@code qits.workload-certificate.enabled=true}) and {@link PlatformTrust#anchorsOnly()}. Not a
 * bean: {@link TlsProxyWiring} builds it when no {@code WorkloadTls} bean exists. Everything is made
 * at run time, nothing is static (native).
 */
final class PlatformWorkloadTls implements WorkloadTls {

  private final WorkloadCertificate workload;
  private final PlatformTrust trust;

  PlatformWorkloadTls(WorkloadCertificate workload, PlatformTrust trust) {
    this.workload = workload;
    this.trust = trust;
  }

  @Override
  public X509Certificate certificate() {
    return workload.current().map(WorkloadCertificate.Current::certificate).orElse(null);
  }

  @Override
  public KeyCertOptions keyCertOptions() {
    return workload.keyCertOptions();
  }

  @Override
  public X509TrustManager clientTrust() {
    return trust.anchorsOnly();
  }

  @Override
  public SSLContext clientContext() {
    try {
      SSLContext context = SSLContext.getInstance("TLS");
      context.init(
          new KeyManager[] {workload.keyManager()}, new TrustManager[] {trust.anchorsOnly()}, null);
      return context;
    } catch (GeneralSecurityException e) {
      throw new IllegalStateException("a TLS context cannot be built in this JVM", e);
    }
  }
}
