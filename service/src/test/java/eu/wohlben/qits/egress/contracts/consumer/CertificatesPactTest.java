package eu.wohlben.qits.egress.contracts.consumer;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import eu.wohlben.qits.egress.tls.LeafDoor;
import eu.wohlben.qits.egress.tls.TlsSelfCheck;
import eu.wohlben.qits.pact.consumer.ConsumerPact;
import eu.wohlben.qits.pact.consumer.GoldenInteraction;
import eu.wohlben.qits.pact.consumer.GoldenMasters;
import eu.wohlben.qits.pact.consumer.Trigger;
import io.vertx.core.Vertx;
import java.io.ByteArrayInputStream;
import java.nio.charset.StandardCharsets;
import java.security.cert.Certificate;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Collection;
import java.util.List;
import java.util.Optional;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.TimeUnit;
import org.junit.jupiter.api.Test;

/**
 * <b>What this service asks qits-certificates-service</b>: one leaf per https target host ({@code
 * POST /certificates/api/leaves}, tls/LeafDoor), pre-issued when a grant table is adopted, renewed
 * at two thirds of its life, and asked inline by a CONNECT with no leaf; and the published anchors
 * ({@code GET /certificates/api/anchors} as JSON, tls/TlsSelfCheck), the only trust of the TLS
 * self-check (qits-2644).
 *
 * <p>The row is driven through the real {@link LeafDoor#post} with the state's own CSR — the one the
 * provider recorded, since a CSR this process builds carries a fresh key and a fresh signature —
 * and the 201 read back the way {@link LeafDoor.Issued#of} reads it.
 *
 * <p>The pact is {@code pacts/qits-egress-service_qits-certificates-service.json}; {@code
 * -Dgolden.update=true} rewrites it.
 */
class CertificatesPactTest {

  static final GoldenMasters CERTIFICATES =
      GoldenMasters.of("qits-certificates-service", "qits-certificates");

  /** The leaf pre-issue (a grant table adopted), renewal, and a CONNECT's inline issue. */
  static final Trigger LEAF_NEEDED = Trigger.event("GrantTableAdopted");

  static final GoldenInteraction LEAF_ISSUED =
      GoldenInteraction.of(LEAF_NEEDED, "leaf issued", "issueLeaf")
          .consumes("certificate", "chain", "serial", "notAfter", "anchorId");

  /** The self-check's anchors: each one's subject and certificate digest, and the version. */
  static final GoldenInteraction ANCHORS_READ =
      GoldenInteraction.of(LEAF_NEEDED, "one ACTIVE anchor", "getAnchors")
          .header("Accept", "application/json")
          .consumes("version", "anchors[].subject", "anchors[].sha256")
          .anyLength("anchors");

  static final ConsumerPact PACT =
      ConsumerPact.of(IdpPactTest.CONSUMER, CERTIFICATES, LEAF_ISSUED, ANCHORS_READ);

  @Test
  void aCsrIsAnsweredWithTheLeafAndItsChain() {
    PACT.run(
        LEAF_ISSUED,
        (url, recorded) -> {
          String csr = recorded.body().path("csr").asText();
          assertTrue(csr.startsWith("-----BEGIN CERTIFICATE REQUEST-----"), "the state's csr: " + csr);
          Vertx vertx = Vertx.vertx();
          try {
            LeafDoor door =
                new LeafDoor(
                    vertx,
                    vertx.createHttpClient(),
                    url + "/certificates",
                    () -> CompletableFuture.completedFuture(Optional.of("contract")),
                    10_000);
            LeafDoor.Answer answer =
                door.post("Bearer contract", csr)
                    .toCompletionStage()
                    .toCompletableFuture()
                    .get(20, TimeUnit.SECONDS);
            assertEquals(201, answer.status(), answer.body());
            LeafDoor.Issued issued = LeafDoor.Issued.of(answer.body());
            List<X509Certificate> chain = certificates(issued.chain());
            assertEquals(2, chain.size(), "the leaf, then the ACTIVE anchor");
            assertEquals(certificates(issued.certificate()).get(0), chain.get(0));
            chain.get(0).verify(chain.get(1).getPublicKey());
            assertTrue(
                chain.get(0).getSubjectAlternativeNames().stream()
                    .anyMatch(name -> "api.example.org".equals(name.get(1))),
                "the leaf names the csr's host");
            assertTrue(issued.serial().matches("[0-9a-f]+"), issued.serial());
          } finally {
            vertx.close();
          }
        });
  }

  @Test
  void theSelfCheckReadsTheAnchorsDigestsAndSubjects() {
    PACT.run(
        ANCHORS_READ,
        (url, recorded) -> {
          Vertx vertx = Vertx.vertx();
          try {
            TlsSelfCheck.Anchors anchors =
                TlsSelfCheck.anchors(vertx.createHttpClient(), url + "/certificates", 10_000)
                    .toCompletableFuture()
                    .get(20, TimeUnit.SECONDS);
            assertEquals(1, anchors.anchors().size());
            assertTrue(
                anchors.anchors().values().iterator().next().startsWith("CN=qits platform CA"),
                anchors.toString());
            assertTrue(anchors.anchors().keySet().iterator().next().matches("[0-9a-f]{64}"));
          } finally {
            vertx.close();
          }
        });
  }

  @Test
  void theCommittedPactIsWhatTheRowsWrite() {
    PACT.compareOrWritePactFile();
  }

  @Test
  void everyInteractionCarriesBothReferences() {
    PACT.assertEveryInteractionCarriesBothReferences();
    assertTrue(PACT.unrecorded().isEmpty(), "every row is recorded: " + PACT.unrecorded());
    assertEquals(PACT.rows().size(), PACT.recorded().size());
  }

  private static List<X509Certificate> certificates(String pem) throws Exception {
    Collection<? extends Certificate> read =
        CertificateFactory.getInstance("X.509")
            .generateCertificates(new ByteArrayInputStream(pem.getBytes(StandardCharsets.US_ASCII)));
    List<X509Certificate> chain = new ArrayList<>();
    read.forEach(c -> chain.add((X509Certificate) c));
    return chain;
  }
}
