package eu.wohlben.qits.egress.tls;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.sun.net.httpserver.HttpServer;
import io.vertx.core.Vertx;
import io.vertx.core.json.JsonObject;
import java.math.BigInteger;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.security.Signature;
import java.security.cert.X509Certificate;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.List;
import java.util.Optional;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.TimeUnit;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

/**
 * {@link LeafDoor} against a fake certificates door on localhost, which signs the CSR it receives
 * with a throwaway {@link TestCa}: the leaf names the host, certifies the key held in memory, and the
 * call carried the {@code qits} bearer.
 */
class LeafDoorTest {

  static final String HOST = "api.example.org";

  static final String TOKEN = "suite-egress-token";

  private TestCa ca;

  private HttpServer server;

  private Vertx vertx;

  private final List<String> authorizations = new CopyOnWriteArrayList<>();

  private final List<String> paths = new CopyOnWriteArrayList<>();

  /** What the fake door answers: 201 with a signed leaf, or this status with an error body. */
  private volatile int refuseWith;

  @BeforeEach
  void start() throws Exception {
    ca = new TestCa();
    server = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
    server.createContext(
        "/",
        exchange -> {
          authorizations.add(exchange.getRequestHeaders().getFirst("Authorization"));
          paths.add(exchange.getRequestMethod() + " " + exchange.getRequestURI().getPath());
          String body = new String(exchange.getRequestBody().readAllBytes(), StandardCharsets.UTF_8);
          int status;
          String answer;
          if (refuseWith != 0) {
            status = refuseWith;
            answer = new JsonObject().put("error", "not a leaf requester").encode();
          } else {
            try {
              Instant now = Instant.now().truncatedTo(ChronoUnit.SECONDS);
              X509Certificate leaf =
                  ca.sign(
                      new JsonObject(body).getString("csr"),
                      now.minusSeconds(300),
                      now.plus(7, ChronoUnit.DAYS),
                      new BigInteger("9511d4330c2fd906e10752af9919d45e", 16));
              String leafPem = LeafKeys.pem("CERTIFICATE", leaf.getEncoded());
              status = 201;
              answer =
                  new JsonObject()
                      .put("certificate", leafPem)
                      .put("chain", leafPem + ca.pem())
                      .put("serial", "9511d4330c2fd906e10752af9919d45e")
                      .put("notAfter", leaf.getNotAfter().toInstant().toString())
                      .put("anchorId", "00000000-0000-4000-8000-000000000001")
                      .encode();
            } catch (Exception e) {
              status = 400;
              answer = new JsonObject().put("error", "bad csr").encode();
            }
          }
          byte[] bytes = answer.getBytes(StandardCharsets.UTF_8);
          exchange.getResponseHeaders().add("Content-Type", "application/json");
          exchange.sendResponseHeaders(status, bytes.length);
          exchange.getResponseBody().write(bytes);
          exchange.close();
        });
    server.start();
    vertx = Vertx.vertx();
  }

  @AfterEach
  void stop() {
    server.stop(0);
    vertx.close();
  }

  private LeafDoor door(Optional<String> token) {
    return new LeafDoor(
        vertx,
        vertx.createHttpClient(),
        "http://127.0.0.1:" + server.getAddress().getPort() + "/certificates/",
        () -> CompletableFuture.completedFuture(token),
        10_000);
  }

  private Leaf issue(LeafDoor door) throws Exception {
    return door.issue(HOST).toCompletableFuture().get(20, TimeUnit.SECONDS);
  }

  @Test
  void theLeafNamesTheHostAndCertifiesTheKeyHeldInMemory() throws Exception {
    Leaf leaf = issue(door(Optional.of(TOKEN)));

    assertEquals(HOST, leaf.host());
    assertEquals(List.of(HOST), LeafKeys.dnsNames(leaf.certificate()));
    assertEquals(2, leaf.chain().length, "the leaf, then the anchor");
    assertArrayEquals(ca.certificate.getEncoded(), leaf.chain()[1].getEncoded());
    leaf.certificate().verify(ca.keys.getPublic());
    assertEquals("EC", leaf.key().getAlgorithm());

    // The key in memory is the one the certificate certifies.
    Signature signer = Signature.getInstance("SHA256withECDSA");
    signer.initSign(leaf.key());
    signer.update(HOST.getBytes(StandardCharsets.UTF_8));
    byte[] signature = signer.sign();
    Signature verifier = Signature.getInstance("SHA256withECDSA");
    verifier.initVerify(leaf.certificate().getPublicKey());
    verifier.update(HOST.getBytes(StandardCharsets.UTF_8));
    assertTrue(verifier.verify(signature));

    assertEquals("9511d4330c2fd906e10752af9919d45e", leaf.serial());
    assertEquals(leaf.certificate().getNotAfter().toInstant(), leaf.notAfter());
    assertEquals("00000000-0000-4000-8000-000000000001", leaf.anchorId());
    assertFalse(leaf.toString().contains("private"), "no key in a message: " + leaf);
  }

  @Test
  void theCallCarriesTheQitsBearerToTheLeavesDoor() throws Exception {
    issue(door(Optional.of(TOKEN)));
    assertEquals(List.of("Bearer " + TOKEN), authorizations);
    assertEquals(List.of("POST /certificates/api/leaves"), paths);
  }

  @Test
  void eachIssueIsANewKey() throws Exception {
    LeafDoor door = door(Optional.of(TOKEN));
    Leaf first = issue(door);
    Leaf second = issue(door);
    assertFalse(
        java.util.Arrays.equals(first.key().getEncoded(), second.key().getEncoded()),
        "a renewal never reuses a key");
  }

  @Test
  void aRefusalFailsWithItsStatus() {
    refuseWith = 403;
    ExecutionException failed = assertThrows(ExecutionException.class, () -> issue(door(Optional.of(TOKEN))));
    LeafIssueFailed refused = assertInstanceOf(LeafIssueFailed.class, failed.getCause());
    assertEquals(403, refused.status());
    assertEquals("not a leaf requester", refused.getMessage());
  }

  @Test
  void withoutABearerNothingIsAsked() {
    ExecutionException failed = assertThrows(ExecutionException.class, () -> issue(door(Optional.empty())));
    assertInstanceOf(LeafIssueFailed.class, failed.getCause());
    assertTrue(paths.isEmpty(), "no call without a bearer: " + paths);
  }

  @Test
  void aChainThatCertifiesAnotherKeyIsRefused() throws Exception {
    LeafKeys.Request mine = LeafKeys.request(HOST);
    LeafKeys.Request theirs = LeafKeys.request(HOST);
    Instant now = Instant.now();
    X509Certificate other = ca.sign(theirs.csrPem(), now.minusSeconds(60), now.plusSeconds(600), BigInteger.TEN);
    String pem = LeafKeys.pem("CERTIFICATE", other.getEncoded());
    String body =
        new JsonObject()
            .put("certificate", pem)
            .put("chain", pem)
            .put("serial", "a")
            .put("notAfter", other.getNotAfter().toInstant().toString())
            .put("anchorId", "x")
            .encode();
    LeafIssueFailed refused =
        assertThrows(LeafIssueFailed.class, () -> LeafDoor.leaf(mine, new LeafDoor.Answer(201, body)));
    assertTrue(refused.getMessage().contains("does not certify"), refused.getMessage());
  }
}
