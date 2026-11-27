package eu.wohlben.qits.egress.identity;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import eu.wohlben.qits.egress.support.SuiteTls;
import eu.wohlben.qits.egress.support.SuiteWorkloads;
import java.util.List;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.KeyPurposeId;
import org.junit.jupiter.api.Test;

/** What a client certificate says about its caller on 8082 (qits-2759), the chain aside. */
class ClientCertificatesTest {

  @Test
  void anApplicationCertificateIsTheApplication() throws Exception {
    SuiteWorkloads.Pair edge = SuiteWorkloads.application("qits-edge");
    ClientCertificates.Identified identified = ClientCertificates.of(edge.certificate());
    assertTrue(identified.verdict().admitted());
    assertEquals(new Principal("application", "qits-edge"), identified.verdict().principal());
    assertEquals(edge.certificate().getSerialNumber().toString(16), identified.serial());
  }

  @Test
  void anAgentCertificateKeepsItsProject() throws Exception {
    ClientCertificates.Identified identified =
        ClientCertificates.of(SuiteWorkloads.agent("a-1", "qits").certificate());
    assertEquals(new Principal("agent", "a-1", "qits"), identified.verdict().principal());
    assertEquals("qits", identified.verdict().principal().project());
  }

  @Test
  void aLeafWithoutClientAuthOrAPrincipalNamesNoOne() throws Exception {
    SuiteWorkloads.Pair leaf =
        SuiteWorkloads.sign(
            SuiteTls.ca(SuiteWorkloads.ANCHOR),
            List.of(
                new GeneralName(
                    GeneralName.uniformResourceIdentifier,
                    SuiteWorkloads.PRINCIPAL + "application:qits-edge")),
            KeyPurposeId.id_kp_serverAuth);
    ClientCertificates.Identified identified = ClientCertificates.of(leaf.certificate());
    assertFalse(identified.verdict().admitted());
    assertEquals(401, identified.verdict().status());
    assertEquals("certificate-no-principal", identified.verdict().reason());
    assertTrue(identified.presented());

    SuiteWorkloads.Pair named =
        SuiteWorkloads.sign(
            SuiteTls.ca(SuiteWorkloads.ANCHOR),
            List.of(new GeneralName(GeneralName.dNSName, "dev-qits-edge")),
            KeyPurposeId.id_kp_clientAuth);
    assertFalse(ClientCertificates.of(named.certificate()).verdict().admitted(), "a CN or DNS name decides nothing");
  }

  @Test
  void noSessionIsNoCredential() {
    ClientCertificates.Identified none = ClientCertificates.of((javax.net.ssl.SSLSession) null);
    assertFalse(none.presented());
    assertEquals("no-credentials", none.verdict().reason());
  }
}
