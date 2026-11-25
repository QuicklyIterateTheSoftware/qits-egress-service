package eu.wohlben.qits.egress.tls;

import java.net.Socket;
import java.security.GeneralSecurityException;
import java.security.KeyStore;
import java.security.MessageDigest;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.HexFormat;
import java.util.Locale;
import java.util.Map;
import javax.net.ssl.SSLEngine;
import javax.net.ssl.TrustManager;
import javax.net.ssl.TrustManagerFactory;
import javax.net.ssl.X509ExtendedTrustManager;

/**
 * <b>Trust in the platform's published anchors, and nothing else</b>: what {@link TlsSelfCheck}'s
 * handshake verifies a leaf against.
 *
 * <p>The anchors are what qits-certificates publishes at {@code GET /certificates/api/anchors} —
 * each one's subject and the SHA-256 of its DER certificate. A server chain is trusted only when one
 * of its certificates IS a published anchor (its DER digest is one of those listed): that
 * certificate becomes the only trust anchor of a standard PKIX validation of the chain, host name
 * included ({@code HTTPS} endpoint identification). The JVM's trust store, and with it every public
 * CA, plays no part; a chain without a published anchor is refused whatever signed it.
 *
 * <p>No randomness and no static state: built per check (native, see AGENTS.md).
 */
final class AnchorTrust extends X509ExtendedTrustManager {

  /** The published anchors: lower-case hex SHA-256 of the DER certificate → subject. */
  private final Map<String, String> anchors;

  private volatile String matchedSubject;

  AnchorTrust(Map<String, String> anchors) {
    this.anchors = Map.copyOf(anchors);
  }

  /** The published subject of the anchor the accepted chain ended in, or null before one. */
  String matchedSubject() {
    return matchedSubject;
  }

  static String sha256(X509Certificate certificate) throws CertificateException {
    try {
      return HexFormat.of()
          .formatHex(MessageDigest.getInstance("SHA-256").digest(certificate.getEncoded()))
          .toLowerCase(Locale.ROOT);
    } catch (GeneralSecurityException e) {
      throw new CertificateException("the certificate cannot be digested", e);
    }
  }

  /** The PKIX manager whose only anchor is the chain's published one. */
  private X509ExtendedTrustManager pinned(X509Certificate[] chain) throws CertificateException {
    if (chain == null || chain.length == 0) {
      throw new CertificateException("the server sent no certificate");
    }
    for (X509Certificate certificate : chain) {
      String subject = anchors.get(sha256(certificate));
      if (subject == null) {
        continue;
      }
      try {
        KeyStore store = KeyStore.getInstance(KeyStore.getDefaultType());
        store.load(null, null);
        store.setCertificateEntry("anchor", certificate);
        TrustManagerFactory factory = TrustManagerFactory.getInstance("PKIX");
        factory.init(store);
        for (TrustManager manager : factory.getTrustManagers()) {
          if (manager instanceof X509ExtendedTrustManager extended) {
            matchedSubject = subject;
            return extended;
          }
        }
      } catch (GeneralSecurityException | java.io.IOException e) {
        throw new CertificateException("the anchor cannot be trusted: " + e.getMessage(), e);
      }
    }
    throw new CertificateException("no certificate of the chain is a published platform anchor");
  }

  @Override
  public void checkServerTrusted(X509Certificate[] chain, String authType, Socket socket)
      throws CertificateException {
    pinned(chain).checkServerTrusted(chain, authType, socket);
  }

  @Override
  public void checkServerTrusted(X509Certificate[] chain, String authType, SSLEngine engine)
      throws CertificateException {
    pinned(chain).checkServerTrusted(chain, authType, engine);
  }

  @Override
  public void checkServerTrusted(X509Certificate[] chain, String authType)
      throws CertificateException {
    // Without a socket there is no host to check: refused, never a weaker check.
    throw new CertificateException("a server is checked with its connection");
  }

  @Override
  public void checkClientTrusted(X509Certificate[] chain, String authType, Socket socket)
      throws CertificateException {
    throw new CertificateException("no client is trusted");
  }

  @Override
  public void checkClientTrusted(X509Certificate[] chain, String authType, SSLEngine engine)
      throws CertificateException {
    throw new CertificateException("no client is trusted");
  }

  @Override
  public void checkClientTrusted(X509Certificate[] chain, String authType)
      throws CertificateException {
    throw new CertificateException("no client is trusted");
  }

  @Override
  public X509Certificate[] getAcceptedIssuers() {
    return new X509Certificate[0];
  }
}
