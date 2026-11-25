package eu.wohlben.qits.egress.tls;

import eu.wohlben.qits.egress.support.SuiteTls;
import jakarta.inject.Singleton;
import java.math.BigInteger;
import java.security.cert.X509Certificate;
import java.time.Duration;
import java.time.Instant;
import java.util.Set;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.CompletionStage;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicLong;

/**
 * The suites' {@link LeafIssuer}, standing in for qits-certificates in every {@code @QuarkusTest}
 * ({@link LeafWiring} takes a {@code LeafIssuer} bean over its {@link LeafDoor}): the real key and
 * CSR ({@link LeafKeys}), signed by {@link SuiteTls#LEAF}, valid seven days. A host in {@link
 * #REFUSED} is answered as qits-certificates' 503.
 */
@Singleton
public class SuiteLeafIssuer implements LeafIssuer {

  /** Hosts whose issuance fails with 503. */
  public static final Set<String> REFUSED = ConcurrentHashMap.newKeySet();

  private static final AtomicLong SERIAL = new AtomicLong(0x5eed00);

  @Override
  public CompletionStage<Leaf> issue(String host) {
    if (REFUSED.contains(host)) {
      return CompletableFuture.failedFuture(new LeafIssueFailed(503, "the suite CA refuses " + host));
    }
    try {
      LeafKeys.Request request = LeafKeys.request(host);
      SuiteTls.Ca ca = SuiteTls.ca(SuiteTls.LEAF);
      Instant now = Instant.now();
      X509Certificate leaf =
          ca.sign(
              request.csrPem(),
              now.minus(Duration.ofHours(1)),
              now.plus(Duration.ofDays(7)),
              BigInteger.valueOf(SERIAL.incrementAndGet()));
      X509Certificate[] chain = {leaf, ca.certificate()};
      LeafKeys.check(request, chain);
      return CompletableFuture.completedFuture(
          new Leaf(
              host,
              request.keys().getPrivate(),
              chain,
              leaf.getSerialNumber().toString(16),
              leaf.getNotBefore().toInstant(),
              leaf.getNotAfter().toInstant(),
              "suite"));
    } catch (Exception e) {
      return CompletableFuture.failedFuture(e);
    }
  }
}
