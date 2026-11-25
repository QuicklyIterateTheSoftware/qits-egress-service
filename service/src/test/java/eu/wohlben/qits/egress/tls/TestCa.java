package eu.wohlben.qits.egress.tls;

import java.io.StringReader;
import java.math.BigInteger;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.SecureRandom;
import java.security.cert.X509Certificate;
import java.security.spec.ECGenParameterSpec;
import java.time.Instant;
import java.util.Date;
import org.bouncycastle.asn1.pkcs.Attribute;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.Extensions;
import org.bouncycastle.asn1.x509.GeneralNames;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.openssl.PEMParser;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.operator.jcajce.JcaContentVerifierProviderBuilder;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.bouncycastle.pkcs.jcajce.JcaPKCS10CertificationRequest;

/**
 * A throwaway CA for the suites: signs a CSR the way qits-certificates does in outline — the SANs of
 * its extensionRequest, the key it carries — after checking its signature.
 */
final class TestCa {

  final KeyPair keys;

  final X509Certificate certificate;

  TestCa() throws Exception {
    KeyPairGenerator generator = KeyPairGenerator.getInstance("EC");
    generator.initialize(new ECGenParameterSpec("secp256r1"), new SecureRandom());
    keys = generator.generateKeyPair();
    X500Name name = new X500Name("CN=egress suite CA");
    Instant now = Instant.now();
    certificate =
        new JcaX509CertificateConverter()
            .getCertificate(
                new JcaX509v3CertificateBuilder(
                        name,
                        BigInteger.ONE,
                        Date.from(now.minusSeconds(3600)),
                        Date.from(now.plusSeconds(86_400 * 30)),
                        name,
                        keys.getPublic())
                    .addExtension(Extension.basicConstraints, true, new BasicConstraints(0))
                    .build(new JcaContentSignerBuilder("SHA256withECDSA").build(keys.getPrivate())));
  }

  String pem() {
    try {
      return LeafKeys.pem("CERTIFICATE", certificate.getEncoded());
    } catch (Exception e) {
      throw new IllegalStateException(e);
    }
  }

  /** The leaf for {@code csrPem}, valid from {@code notBefore} to {@code notAfter}. */
  X509Certificate sign(String csrPem, Instant notBefore, Instant notAfter, BigInteger serial)
      throws Exception {
    PKCS10CertificationRequest csr;
    try (PEMParser parser = new PEMParser(new StringReader(csrPem))) {
      csr = (PKCS10CertificationRequest) parser.readObject();
    }
    JcaPKCS10CertificationRequest request = new JcaPKCS10CertificationRequest(csr);
    if (!csr.isSignatureValid(
        new JcaContentVerifierProviderBuilder().build(request.getPublicKey()))) {
      throw new IllegalArgumentException("the csr signature does not verify");
    }
    Attribute[] attributes = csr.getAttributes(PKCSObjectIdentifiers.pkcs_9_at_extensionRequest);
    GeneralNames names =
        GeneralNames.fromExtensions(
            Extensions.getInstance(attributes[0].getAttrValues().getObjectAt(0)),
            Extension.subjectAlternativeName);
    X500Name subject = new X500Name("CN=" + names.getNames()[0].getName());
    return new JcaX509CertificateConverter()
        .getCertificate(
            new JcaX509v3CertificateBuilder(
                    new X500Name(certificate.getSubjectX500Principal().getName()),
                    serial,
                    Date.from(notBefore),
                    Date.from(notAfter),
                    subject,
                    request.getPublicKey())
                .addExtension(Extension.basicConstraints, true, new BasicConstraints(false))
                .addExtension(Extension.subjectAlternativeName, false, names)
                .build(new JcaContentSignerBuilder("SHA256withECDSA").build(keys.getPrivate())));
  }
}
