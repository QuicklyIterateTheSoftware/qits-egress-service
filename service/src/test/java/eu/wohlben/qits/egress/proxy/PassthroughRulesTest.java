package eu.wohlben.qits.egress.proxy;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.net.InetAddress;
import org.junit.jupiter.api.Test;

/** The passthrough's pure rules (qits-2654): which addresses are public, which names are refused. */
class PassthroughRulesTest {

  private static boolean isPublic(String literal) throws Exception {
    return Passthrough.isPublic(InetAddress.getByName(literal));
  }

  @Test
  void everyNonPublicRangeIsRefused() throws Exception {
    for (String literal :
        new String[] {
          "127.0.0.1", "127.1.2.3", "0.0.0.0", "0.1.2.3", "10.0.0.1", "10.255.255.255",
          "172.16.0.1", "172.31.255.255", "192.168.1.1", "169.254.169.254", "100.64.0.1",
          "100.127.255.255", "224.0.0.1", "239.255.255.250", "240.0.0.1", "255.255.255.255",
          "::", "::1", "fc00::1", "fd12:3456::1", "fe80::1", "ff02::1", "::ffff:10.0.0.1",
          "::ffff:127.0.0.1", "64:ff9b::a00:1", "::10.0.0.1"
        }) {
      assertFalse(isPublic(literal), literal + " is not public");
    }
  }

  @Test
  void publicAddressesPass() throws Exception {
    for (String literal :
        new String[] {
          "1.1.1.1", "8.8.8.8", "172.15.255.255", "172.32.0.1", "100.63.255.255", "100.128.0.1",
          "192.169.0.1", "203.0.113.7", "2606:4700::1111", "64:ff9b::808:808", "::ffff:8.8.8.8"
        }) {
      assertTrue(isPublic(literal), literal + " is public");
    }
  }

  @Test
  void platformAndSingleLabelNamesAreRefusedBeforeAnyLookup() {
    String platform = "qits.wohlben.eu";
    assertEquals(Passthrough.PLATFORM_HOST, Passthrough.nameRefusal("qits.wohlben.eu", platform));
    assertEquals(Passthrough.PLATFORM_HOST, Passthrough.nameRefusal("idp.qits.wohlben.eu", platform));
    assertEquals(Passthrough.PLATFORM_HOST, Passthrough.nameRefusal("a.b.qits.wohlben.eu.", platform));
    assertEquals(Passthrough.PLATFORM_HOST, Passthrough.nameRefusal("IDP.QITS.WOHLBEN.EU", platform));
    assertNull(Passthrough.nameRefusal("wohlben.eu", platform));
    assertNull(Passthrough.nameRefusal("notqits.wohlben.eu", platform));
    assertEquals(Passthrough.SINGLE_LABEL, Passthrough.nameRefusal("dev-qits-idp", platform));
    assertEquals(Passthrough.SINGLE_LABEL, Passthrough.nameRefusal("localhost", platform));
    assertEquals(Passthrough.SINGLE_LABEL, Passthrough.nameRefusal("localhost.", platform));
    assertNull(Passthrough.nameRefusal("api.github.com", platform));
    // An IP literal is judged by its address, not as a name.
    assertNull(Passthrough.nameRefusal("10.0.0.1", platform));
    assertNull(Passthrough.nameRefusal("::1", platform));
  }
}
