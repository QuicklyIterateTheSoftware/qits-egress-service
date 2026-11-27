package eu.wohlben.qits.egress.tls;

import eu.wohlben.qits.trust.PlatformTrust;
import eu.wohlben.qits.trust.WorkloadCertificate;
import jakarta.enterprise.inject.Instance;
import jakarta.inject.Inject;
import jakarta.inject.Singleton;

/**
 * Which {@link WorkloadTls} the TLS proxy listener uses (qits-2759): a {@code WorkloadTls} bean
 * when there is one (the suites' throwaway CA), else the platform's, {@link PlatformWorkloadTls}.
 */
@Singleton
public class TlsProxyWiring {

  @Inject Instance<WorkloadTls> beans;

  @Inject WorkloadCertificate workload;

  @Inject PlatformTrust trust;

  private volatile WorkloadTls tls;

  /** The listener's identity and client trust; made once, on first use. */
  public WorkloadTls tls() {
    WorkloadTls current = tls;
    if (current == null) {
      current = beans.isResolvable() ? beans.get() : new PlatformWorkloadTls(workload, trust);
      tls = current;
    }
    return current;
  }
}
