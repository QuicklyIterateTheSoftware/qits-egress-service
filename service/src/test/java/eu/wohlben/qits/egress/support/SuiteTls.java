package eu.wohlben.qits.egress.support;

import java.io.IOException;
import java.io.StringReader;
import java.io.UncheckedIOException;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.SecureRandom;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.PKCS8EncodedKeySpec;
import java.time.Instant;
import java.util.Base64;
import java.util.Date;
import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManagerFactory;
import org.bouncycastle.asn1.pkcs.Attribute;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.Extensions;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.GeneralNames;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.openssl.PEMParser;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.operator.jcajce.JcaContentVerifierProviderBuilder;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.bouncycastle.pkcs.jcajce.JcaPKCS10CertificationRequest;

/**
 * <b>Throwaway CAs for the interception suites</b> (qits-2644), the same in every class loader of
 * the JVM: a {@code @QuarkusTest}'s config source, its beans and its test class each load this class
 * on their own, so each CA is written once to a directory parked in a system property and read back
 * by whichever loader asks next.
 *
 * <ul>
 *   <li>{@link #LEAF} stands in for qits-certificates: it signs the egress' leaf CSRs; a client of
 *       the tunnel trusts it.
 *   <li>{@link #UPSTREAM} signs the fake third party's certificate; the egress' upstream pools trust
 *       it through {@code qits.egress.test.upstream-trust}, the suites' only way past the JVM's
 *       trust store.
 * </ul>
 */
public final class SuiteTls {

  public static final String LEAF = "leaf";

  public static final String UPSTREAM = "upstream";

  static final String DIRECTORY_PROPERTY = "qits.test.egress.tls-dir";

  private SuiteTls() {}

  /** One CA: its key, its self-signed certificate and where that certificate's PEM is. */
  public record Ca(String name, KeyPair keys, X509Certificate certificate, Path pem) {

    /** The leaf {@code csrPem} asks for — its key and its SAN dNSNames — valid as given. */
    public X509Certificate sign(String csrPem, Instant notBefore, Instant notAfter, BigInteger serial)
        throws Exception {
      PKCS10CertificationRequest csr;
      try (PEMParser parser = new PEMParser(new StringReader(csrPem))) {
        csr = (PKCS10CertificationRequest) parser.readObject();
      }
      JcaPKCS10CertificationRequest request = new JcaPKCS10CertificationRequest(csr);
      if (!csr.isSignatureValid(new JcaContentVerifierProviderBuilder().build(request.getPublicKey()))) {
        throw new IllegalArgumentException("the csr signature does not verify");
      }
      Attribute[] attributes = csr.getAttributes(PKCSObjectIdentifiers.pkcs_9_at_extensionRequest);
      GeneralNames names =
          GeneralNames.fromExtensions(
              Extensions.getInstance(attributes[0].getAttrValues().getObjectAt(0)),
              Extension.subjectAlternativeName);
      return leaf(request.getPublicKey(), names, notBefore, notAfter, serial);
    }

    /** A server certificate for {@code host}, with a fresh key: a {@link KeyManagerFactory}. */
    public KeyManagerFactory server(String host) throws Exception {
      KeyPair server = ec();
      Instant now = Instant.now();
      X509Certificate certificate =
          leaf(
              server.getPublic(),
              new GeneralNames(new GeneralName(GeneralName.dNSName, host)),
              now.minusSeconds(3600),
              now.plusSeconds(86_400),
              BigInteger.valueOf(System.nanoTime()));
      KeyStore store = KeyStore.getInstance("PKCS12");
      store.load(null, null);
      store.setKeyEntry(
          "server", server.getPrivate(), new char[0], new X509Certificate[] {certificate, this.certificate});
      KeyManagerFactory factory = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
      factory.init(store, new char[0]);
      return factory;
    }

    /** A client context trusting this CA and nothing else. */
    public SSLContext clientContext() throws Exception {
      KeyStore store = KeyStore.getInstance("PKCS12");
      store.load(null, null);
      store.setCertificateEntry("ca", certificate);
      TrustManagerFactory trust = TrustManagerFactory.getInstance("PKIX");
      trust.init(store);
      SSLContext context = SSLContext.getInstance("TLS");
      context.init(null, trust.getTrustManagers(), new SecureRandom());
      return context;
    }

    private X509Certificate leaf(
        java.security.PublicKey key,
        GeneralNames names,
        Instant notBefore,
        Instant notAfter,
        BigInteger serial)
        throws Exception {
      X500Name subject = new X500Name("CN=" + names.getNames()[0].getName());
      return new JcaX509CertificateConverter()
          .getCertificate(
              new JcaX509v3CertificateBuilder(
                      new X500Name(certificate.getSubjectX500Principal().getName()),
                      serial,
                      Date.from(notBefore),
                      Date.from(notAfter),
                      subject,
                      key)
                  .addExtension(Extension.basicConstraints, true, new BasicConstraints(false))
                  .addExtension(Extension.subjectAlternativeName, false, names)
                  .build(new JcaContentSignerBuilder("SHA256withECDSA").build(keys.getPrivate())));
    }
  }

  /** The CA called {@code name}, made on first use in this JVM. */
  public static Ca ca(String name) {
    // System.getProperties() is one object for every class loader of the JVM.
    synchronized (System.getProperties()) {
      try {
        Path directory = directory();
        Path keyFile = directory.resolve(name + "-ca.key");
        Path pemFile = directory.resolve(name + "-ca.pem");
        if (!Files.exists(pemFile)) {
          write(name, keyFile, pemFile);
        }
        X509Certificate certificate =
            (X509Certificate)
                CertificateFactory.getInstance("X.509")
                    .generateCertificate(Files.newInputStream(pemFile));
        PrivateKey key =
            KeyFactory.getInstance("EC")
                .generatePrivate(new PKCS8EncodedKeySpec(Files.readAllBytes(keyFile)));
        return new Ca(name, new KeyPair(certificate.getPublicKey(), key), certificate, pemFile);
      } catch (IOException e) {
        throw new UncheckedIOException(e);
      } catch (Exception e) {
        throw new IllegalStateException("the suite CA " + name + " cannot be made", e);
      }
    }
  }

  private static Path directory() throws IOException {
    String parked = System.getProperty(DIRECTORY_PROPERTY);
    if (parked != null) {
      return Path.of(parked);
    }
    Path directory = Files.createTempDirectory("egress-suite-tls");
    directory.toFile().deleteOnExit();
    System.setProperty(DIRECTORY_PROPERTY, directory.toString());
    return directory;
  }

  private static void write(String name, Path keyFile, Path pemFile) throws Exception {
    KeyPair keys = ec();
    X500Name subject = new X500Name("CN=egress suite " + name + " CA");
    Instant now = Instant.now();
    X509Certificate certificate =
        new JcaX509CertificateConverter()
            .getCertificate(
                new JcaX509v3CertificateBuilder(
                        subject,
                        BigInteger.ONE,
                        Date.from(now.minusSeconds(3600)),
                        Date.from(now.plusSeconds(86_400L * 30)),
                        subject,
                        keys.getPublic())
                    .addExtension(Extension.basicConstraints, true, new BasicConstraints(0))
                    .build(new JcaContentSignerBuilder("SHA256withECDSA").build(keys.getPrivate())));
    Files.write(keyFile, keys.getPrivate().getEncoded());
    Files.writeString(pemFile, pem(certificate), StandardCharsets.US_ASCII);
    keyFile.toFile().deleteOnExit();
    pemFile.toFile().deleteOnExit();
  }

  /** A certificate as PEM. */
  public static String pem(X509Certificate certificate) throws Exception {
    String body =
        Base64.getMimeEncoder(64, "\n".getBytes(StandardCharsets.US_ASCII))
            .encodeToString(certificate.getEncoded());
    return "-----BEGIN CERTIFICATE-----\n" + body + "\n-----END CERTIFICATE-----\n";
  }

  private static KeyPair ec() throws Exception {
    KeyPairGenerator generator = KeyPairGenerator.getInstance("EC");
    generator.initialize(new ECGenParameterSpec("secp256r1"), new SecureRandom());
    return generator.generateKeyPair();
  }
}
