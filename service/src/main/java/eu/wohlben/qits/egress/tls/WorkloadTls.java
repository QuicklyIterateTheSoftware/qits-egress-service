package eu.wohlben.qits.egress.tls;

import io.vertx.core.net.KeyCertOptions;
import java.security.cert.X509Certificate;
import javax.net.ssl.SSLContext;
import javax.net.ssl.X509TrustManager;

/**
 * <b>The TLS proxy listener's own identity and its client trust</b> (epic qits-2626, qits-2759).
 * In a deployment it is {@link PlatformWorkloadTls}: this service's workload certificate from
 * qits-certificates ({@code WorkloadCertificate}, qits-2758) and the platform anchors alone ({@code
 * PlatformTrust.anchorsOnly()}). A bean of this type replaces it, as the suites' {@code
 * SuiteWorkloadTls} does ({@link TlsProxyWiring}), the way a {@link LeafIssuer} bean replaces the
 * leaf door.
 */
public interface WorkloadTls {

  /** The server certificate held now, or null while none is: 8082 stays closed until one is. */
  X509Certificate certificate();

  /** The server key and chain, picked per handshake, so a renewal is served on the next one. */
  KeyCertOptions keyCertOptions();

  /**
   * Whom a client certificate may chain to: the platform anchors only, never a public CA. It is a
   * PKIX trust manager, so a client chain must also carry EKU clientAuth (an interception leaf,
   * serverAuth only, fails the handshake).
   */
  X509TrustManager clientTrust();

  /** A client context presenting this service's own certificate, trusting the anchors only. */
  SSLContext clientContext();
}
