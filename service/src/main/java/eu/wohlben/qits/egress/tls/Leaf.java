package eu.wohlben.qits.egress.tls;

import java.security.PrivateKey;
import java.security.cert.X509Certificate;
import java.time.Duration;
import java.time.Instant;

/**
 * One host's leaf: the key this process generated for it and the chain qits-certificates signed —
 * what a {@code KeyManager} picking by SNI needs ({@link #key()} and {@link #chain()}, leaf first).
 *
 * <p><b>The key never leaves the process.</b> It is held here and nowhere else: never written,
 * never logged. {@link #toString()} names the host, the serial and the validity only, so a log line
 * or an assertion message that prints a leaf prints no key.
 *
 * @param host the target host, lower case: the leaf's one dNSName
 * @param key the leaf's EC P-256 private key, in memory only
 * @param chain the leaf certificate first, then the anchor that signed it
 * @param serial the leaf's serial, hex
 * @param notBefore the leaf's notBefore
 * @param notAfter the leaf's notAfter
 * @param anchorId the qits-certificates anchor that signed it
 */
public record Leaf(
    String host,
    PrivateKey key,
    X509Certificate[] chain,
    String serial,
    Instant notBefore,
    Instant notAfter,
    String anchorId) {

  public Leaf {
    chain = chain.clone();
  }

  /** The chain, leaf first; a copy. */
  @Override
  public X509Certificate[] chain() {
    return chain.clone();
  }

  /** The leaf certificate itself. */
  public X509Certificate certificate() {
    return chain[0];
  }

  /** Whether the leaf may be served at {@code now}. */
  public boolean validAt(Instant now) {
    return !now.isBefore(notBefore) && now.isBefore(notAfter);
  }

  /** When it is renewed: {@code fraction} of the way from notBefore to notAfter. */
  public Instant renewAt(double fraction) {
    long life = Duration.between(notBefore, notAfter).toMillis();
    return notBefore.plusMillis((long) (life * fraction));
  }

  /** No key, ever. */
  @Override
  public String toString() {
    return "Leaf[host="
        + host
        + ", serial="
        + serial
        + ", notBefore="
        + notBefore
        + ", notAfter="
        + notAfter
        + ", anchorId="
        + anchorId
        + "]";
  }
}
