package eu.wohlben.qits.egress.support;

import java.math.BigInteger;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.SecureRandom;
import java.security.cert.X509Certificate;
import java.security.spec.ECGenParameterSpec;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;
import java.util.concurrent.atomic.AtomicLong;
import javax.net.ssl.KeyManager;
import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManager;
import javax.net.ssl.TrustManagerFactory;
import javax.net.ssl.X509KeyManager;
import javax.net.ssl.X509TrustManager;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.ExtendedKeyUsage;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.GeneralNames;
import org.bouncycastle.asn1.x509.KeyPurposeId;
import org.bouncycastle.asn1.x509.KeyUsage;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;

/**
 * <b>Workload certificates for the TLS proxy suites</b> (qits-2759), signed by {@link SuiteTls}'s
 * {@value #ANCHOR} CA, which stands in for the platform anchors: what qits-certificates' workload
 * door issues (URI SANs, EKU clientAuth, + serverAuth and the wire alias for an application), and
 * the shapes the listener must refuse (an interception leaf, a certificate of another CA, two
 * principals).
 */
public final class SuiteWorkloads {

  /** The CA the suites' 8082 trusts, as a deployment trusts the platform anchors. */
  public static final String ANCHOR = "workload";

  /** Another CA, trusted by nothing on 8082. */
  public static final String STRANGER = "stranger";

  public static final String PRINCIPAL = "urn:qits:principal:";

  private static final AtomicLong SERIALS = new AtomicLong(System.nanoTime() & 0xffffffffL);

  private SuiteWorkloads() {}

  /** A key and its chain (the certificate, then its CA). */
  public record Pair(KeyPair keys, X509Certificate certificate, X509Certificate ca) {

    public X509KeyManager keyManager() throws Exception {
      KeyStore store = KeyStore.getInstance("PKCS12");
      store.load(null, null);
      store.setKeyEntry(
          "workload", keys.getPrivate(), new char[0], new X509Certificate[] {certificate, ca});
      KeyManagerFactory factory =
          KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
      factory.init(store, new char[0]);
      return (X509KeyManager) factory.getKeyManagers()[0];
    }
  }

  /** {@code application:<app>}'s certificate as the door issues it: alias, both usages. */
  public static Pair application(String app) throws Exception {
    return sign(
        SuiteTls.ca(ANCHOR),
        List.of(
            new GeneralName(GeneralName.uniformResourceIdentifier, PRINCIPAL + "application:" + app),
            new GeneralName(GeneralName.dNSName, "dev-" + app),
            new GeneralName(GeneralName.dNSName, "localhost")),
        KeyPurposeId.id_kp_clientAuth,
        KeyPurposeId.id_kp_serverAuth);
  }

  /** An agent's certificate: the agent and its project, clientAuth only. */
  public static Pair agent(String agent, String project) throws Exception {
    return sign(
        SuiteTls.ca(ANCHOR),
        List.of(
            new GeneralName(GeneralName.uniformResourceIdentifier, PRINCIPAL + "agent:" + agent),
            new GeneralName(GeneralName.uniformResourceIdentifier, "urn:qits:project:" + project)),
        KeyPurposeId.id_kp_clientAuth);
  }

  /** Any certificate: these names and these usages, from {@code ca}. */
  public static Pair sign(SuiteTls.Ca ca, List<GeneralName> names, KeyPurposeId... purposes)
      throws Exception {
    KeyPair keys = ec();
    Instant now = Instant.now();
    JcaX509v3CertificateBuilder builder =
        new JcaX509v3CertificateBuilder(
            new X500Name(ca.certificate().getSubjectX500Principal().getName()),
            BigInteger.valueOf(SERIALS.incrementAndGet()),
            Date.from(now.minusSeconds(300)),
            Date.from(now.plusSeconds(86_400)),
            new X500Name("CN=suite workload"),
            keys.getPublic());
    builder.addExtension(Extension.basicConstraints, true, new BasicConstraints(false));
    builder.addExtension(Extension.keyUsage, true, new KeyUsage(KeyUsage.digitalSignature));
    if (purposes.length > 0) {
      builder.addExtension(Extension.extendedKeyUsage, false, new ExtendedKeyUsage(purposes));
    }
    if (!names.isEmpty()) {
      builder.addExtension(
          Extension.subjectAlternativeName,
          false,
          new GeneralNames(names.toArray(GeneralName[]::new)));
    }
    X509Certificate certificate =
        new JcaX509CertificateConverter()
            .getCertificate(
                builder.build(
                    new JcaContentSignerBuilder("SHA256withECDSA").build(ca.keys().getPrivate())));
    return new Pair(keys, certificate, ca.certificate());
  }

  /** PKIX trust in {@code ca} alone. */
  public static X509TrustManager trust(String ca) throws Exception {
    KeyStore store = KeyStore.getInstance("PKCS12");
    store.load(null, null);
    store.setCertificateEntry("ca", SuiteTls.ca(ca).certificate());
    TrustManagerFactory factory = TrustManagerFactory.getInstance("PKIX");
    factory.init(store);
    return (X509TrustManager) factory.getTrustManagers()[0];
  }

  /**
   * A client context presenting {@code pair} (none when null) and trusting the {@value #ANCHOR}
   * CA, where the suites' egress certificate comes from.
   */
  public static SSLContext client(Pair pair) throws Exception {
    List<KeyManager> keys = new ArrayList<>();
    if (pair != null) {
      keys.add(pair.keyManager());
    }
    SSLContext context = SSLContext.getInstance("TLS");
    context.init(
        keys.toArray(KeyManager[]::new), new TrustManager[] {trust(ANCHOR)}, new SecureRandom());
    return context;
  }

  /**
   * As {@link #client}, but presenting {@code pair} whatever issuers the server asks for: a JDK
   * client would otherwise keep a stranger's certificate to itself, and the server's trust would
   * never be put to the test.
   */
  public static SSLContext clientInsisting(Pair pair) throws Exception {
    X509KeyManager keys = pair.keyManager();
    javax.net.ssl.X509ExtendedKeyManager insisting =
        new javax.net.ssl.X509ExtendedKeyManager() {
          @Override
          public String[] getClientAliases(String keyType, java.security.Principal[] issuers) {
            return new String[] {"workload"};
          }

          @Override
          public String chooseClientAlias(
              String[] keyType, java.security.Principal[] issuers, java.net.Socket socket) {
            return "workload";
          }

          @Override
          public String chooseEngineClientAlias(
              String[] keyType, java.security.Principal[] issuers, javax.net.ssl.SSLEngine engine) {
            return "workload";
          }

          @Override
          public String[] getServerAliases(String keyType, java.security.Principal[] issuers) {
            return null;
          }

          @Override
          public String chooseServerAlias(
              String keyType, java.security.Principal[] issuers, java.net.Socket socket) {
            return null;
          }

          @Override
          public X509Certificate[] getCertificateChain(String alias) {
            return keys.getCertificateChain(alias);
          }

          @Override
          public java.security.PrivateKey getPrivateKey(String alias) {
            return keys.getPrivateKey(alias);
          }
        };
    SSLContext context = SSLContext.getInstance("TLS");
    context.init(
        new KeyManager[] {insisting}, new TrustManager[] {trust(ANCHOR)}, new SecureRandom());
    return context;
  }

  private static KeyPair ec() throws Exception {
    KeyPairGenerator generator = KeyPairGenerator.getInstance("EC");
    generator.initialize(new ECGenParameterSpec("secp256r1"), new SecureRandom());
    return generator.generateKeyPair();
  }
}
