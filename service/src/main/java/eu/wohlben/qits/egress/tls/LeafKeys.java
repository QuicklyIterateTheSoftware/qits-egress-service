package eu.wohlben.qits.egress.tls;

import java.io.ByteArrayInputStream;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.SecureRandom;
import java.security.cert.CertificateFactory;
import java.security.cert.CertificateParsingException;
import java.security.cert.X509Certificate;
import java.security.spec.ECGenParameterSpec;
import java.util.Arrays;
import java.util.Base64;
import java.util.Collection;
import java.util.List;
import java.util.Locale;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.ExtensionsGenerator;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.GeneralNames;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.bouncycastle.pkcs.jcajce.JcaPKCS10CertificationRequestBuilder;

/**
 * The crypto of one leaf: an EC P-256 key and its PKCS#10 CSR, and the check of the chain that
 * comes back. Keys and signatures are the JDK's (SunEC); Bouncy Castle only assembles the request.
 *
 * <p><b>NATIVE: nothing here holds randomness.</b> Every {@link SecureRandom} and {@link
 * KeyPairGenerator} is created per call: a native image refuses one seeded at build time in its
 * image heap (qits-certificates' first native release failed on exactly that).
 */
final class LeafKeys {

  /** The curve of every leaf key. */
  static final String CURVE = "secp256r1";

  static final String SIGNATURE = "SHA256withECDSA";

  private LeafKeys() {}

  /** A key and the CSR naming {@code host}, before anything is sent. */
  record Request(String host, KeyPair keys, String csrPem) {

    /** No key in a message. */
    @Override
    public String toString() {
      return "Request[host=" + host + "]";
    }
  }

  /**
   * A fresh EC P-256 key and its CSR: subject {@code CN=<host>} (qits-certificates ignores it), an
   * extensionRequest carrying the SAN {@code dNSName:<host>}, signed {@code SHA256withECDSA}.
   */
  static Request request(String host) throws GeneralSecurityException {
    KeyPairGenerator generator = KeyPairGenerator.getInstance("EC");
    generator.initialize(new ECGenParameterSpec(CURVE), new SecureRandom());
    KeyPair keys = generator.generateKeyPair();
    try {
      ExtensionsGenerator extensions = new ExtensionsGenerator();
      extensions.addExtension(
          Extension.subjectAlternativeName,
          false,
          new GeneralNames(new GeneralName(GeneralName.dNSName, host)));
      PKCS10CertificationRequest csr =
          new JcaPKCS10CertificationRequestBuilder(new X500Name("CN=" + host), keys.getPublic())
              .addAttribute(
                  PKCSObjectIdentifiers.pkcs_9_at_extensionRequest, extensions.generate())
              .build(
                  new JcaContentSignerBuilder(SIGNATURE)
                      .setSecureRandom(new SecureRandom())
                      .build(keys.getPrivate()));
      return new Request(host, keys, pem("CERTIFICATE REQUEST", csr.getEncoded()));
    } catch (OperatorCreationException | java.io.IOException e) {
      throw new GeneralSecurityException(
          "the csr could not be built: " + e.getClass().getSimpleName(), e);
    }
  }

  /** {@code -----BEGIN <type>-----}, base64 in 64-column lines, {@code -----END <type>-----}. */
  static String pem(String type, byte[] der) {
    String body =
        Base64.getMimeEncoder(64, "\n".getBytes(StandardCharsets.US_ASCII)).encodeToString(der);
    return "-----BEGIN " + type + "-----\n" + body + "\n-----END " + type + "-----\n";
  }

  /** Every certificate of a PEM bundle, in order. */
  static X509Certificate[] certificates(String pem) throws GeneralSecurityException {
    Collection<? extends java.security.cert.Certificate> read =
        CertificateFactory.getInstance("X.509")
            .generateCertificates(
                new ByteArrayInputStream(pem.getBytes(StandardCharsets.US_ASCII)));
    return read.stream().map(X509Certificate.class::cast).toArray(X509Certificate[]::new);
  }

  /**
   * The chain answers the request: its first certificate holds the request's public key and names
   * {@code host} among its dNSNames.
   *
   * @throws GeneralSecurityException naming what does not match, never a key
   */
  static void check(Request request, X509Certificate[] chain) throws GeneralSecurityException {
    if (chain.length == 0) {
      throw new GeneralSecurityException("the answer holds no certificate");
    }
    X509Certificate leaf = chain[0];
    if (!Arrays.equals(
        leaf.getPublicKey().getEncoded(), request.keys().getPublic().getEncoded())) {
      throw new GeneralSecurityException("the leaf does not certify the key this process holds");
    }
    if (!dnsNames(leaf).contains(request.host())) {
      throw new GeneralSecurityException("the leaf does not name " + request.host());
    }
  }

  /** A certificate's dNSNames, lower case. */
  static List<String> dnsNames(X509Certificate certificate) throws CertificateParsingException {
    Collection<List<?>> names = certificate.getSubjectAlternativeNames();
    if (names == null) {
      return List.of();
    }
    return names.stream()
        .filter(name -> name.size() >= 2 && Integer.valueOf(GeneralName.dNSName).equals(name.get(0)))
        .map(name -> String.valueOf(name.get(1)).toLowerCase(Locale.ROOT))
        .toList();
  }
}
