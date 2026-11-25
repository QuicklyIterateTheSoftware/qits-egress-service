package eu.wohlben.qits.egress.tls;

import eu.wohlben.qits.egress.grants.GrantIndex;
import eu.wohlben.qits.egress.grants.GrantRoute;
import eu.wohlben.qits.egress.grants.GrantTableAdopted;
import eu.wohlben.qits.egress.proxy.EgressProxy;
import io.quarkus.runtime.ShutdownEvent;
import io.quarkus.runtime.StartupEvent;
import io.vertx.core.Vertx;
import io.vertx.core.http.HttpClient;
import io.vertx.core.http.HttpClientOptions;
import io.vertx.core.http.HttpHeaders;
import io.vertx.core.http.HttpMethod;
import io.vertx.core.http.RequestOptions;
import io.vertx.core.json.JsonArray;
import io.vertx.core.json.JsonObject;
import jakarta.annotation.PostConstruct;
import jakarta.enterprise.event.Observes;
import jakarta.inject.Inject;
import jakarta.inject.Singleton;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.math.BigInteger;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.security.cert.X509Certificate;
import java.time.Duration;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Objects;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.CompletionException;
import java.util.concurrent.CompletionStage;
import java.util.function.Predicate;
import java.util.function.Supplier;
import javax.net.ssl.SNIHostName;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLParameters;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.TrustManager;
import org.eclipse.microprofile.config.inject.ConfigProperty;

/**
 * <b>The live proof that the egress ends TLS with a platform-issued leaf</b> (epic qits-2524,
 * qits-2644, dossier "Egress TLS interception", "Self-check").
 *
 * <p>When the table in force grants THIS application ({@code application:qits-egress}) the route
 * {@value #ROUTE} — {@code .config/qits/egress.yml} declares it for {@code https://api.hetzner.cloud}
 * with {@code methods: [CONNECT, HEAD]} — and the leaf for its host is held, the egress:
 *
 * <ol>
 *   <li>reads the platform anchors, {@code GET <certificates-url>/api/anchors} as JSON (each
 *       anchor's subject and the SHA-256 of its certificate; the door is public);
 *   <li>opens {@code CONNECT <host>:<port>} on its own proxy listener ({@code 127.0.0.1:8081}) with
 *       {@code Proxy-Authorization: Bearer <its own qits client token>};
 *   <li>handshakes inside the tunnel trusting ONLY those anchors ({@link AnchorTrust}: the chain
 *       must hold a certificate whose digest is published, which is then the one PKIX anchor; host
 *       name checked);
 *   <li>sends {@code HEAD /v1/} (reads nothing) and reads the status line.
 * </ol>
 *
 * <p>One line on logger {@code eu.wohlben.qits.egress.tls}: INFO {@code egress tls self-check ok
 * host=<h> leafSerial=<hex> issuer=<anchor subject> status=<n>}, or WARN {@code egress tls
 * self-check failed host=<h> reason=<r> retryIn=<d>}. A failure retries after a backoff doubling
 * from {@code qits.egress.leaves.backoff-min} (30 s) to {@code backoff-max} (10 min). It runs again
 * when the route's target changes and whenever the anchors' version moves (read every {@code
 * qits.egress.tls.self-check.anchors-interval}, 10 min). The status is the upstream's — a 502
 * {@code secret not configured} while the route's secret is not held still proves the TLS chain.
 *
 * <p><b>Never part of readiness.</b> Nothing waits for it and nothing fails because of it.
 */
@Singleton
public class TlsSelfCheck {

  /** The route the check rides, granted to this application. */
  public static final String ROUTE = "tls-self-check";

  /** The request sent inside the tunnel. */
  static final String PATH = "/v1/";

  /** How often a check whose leaf is not held yet looks again, quietly, before it runs anyway. */
  static final Duration LEAF_POLL = Duration.ofSeconds(5);

  /** How many {@link #LEAF_POLL}s a check waits for its leaf. */
  static final int LEAF_POLLS = 24;

  @Inject Vertx vertx;

  @Inject GrantIndex index;

  @Inject LeafCertificates leaves;

  @Inject LeafBearer bearer;

  @Inject EgressProxy proxy;

  @ConfigProperty(name = "quarkus.application.name", defaultValue = "qits-egress")
  String application;

  @ConfigProperty(name = "qits.egress.certificates-url")
  String certificatesUrl;

  @ConfigProperty(name = "qits.egress.tls.self-check.enabled", defaultValue = "true")
  boolean enabled;

  @ConfigProperty(name = "qits.egress.tls.self-check.anchors-interval", defaultValue = "10m")
  Duration anchorsInterval;

  @ConfigProperty(name = "qits.egress.leaves.backoff-min", defaultValue = "30s")
  Duration backoffMin;

  @ConfigProperty(name = "qits.egress.leaves.backoff-max", defaultValue = "10m")
  Duration backoffMax;

  @ConfigProperty(name = "qits.egress.leaves.timeout", defaultValue = "10s")
  Duration timeout;

  private HttpClient client;

  private Runner runner;

  private long timer = -1;

  @PostConstruct
  void build() {
    // A small client of its own; TLS by the JVM trust store (quarkus.ssl.native), as LeafDoor's.
    client = vertx.createHttpClient(new HttpClientOptions().setKeepAlive(false).setVerifyHost(true));
    runner =
        new Runner(
            this::anchors,
            this::probe,
            host -> leaves.leafFor(host).isPresent(),
            (delay, task) -> vertx.setTimer(Math.max(1, delay.toMillis()), id -> task.run()),
            new Runner.Sink() {
              @Override
              public void ok(String line) {
                LeafCertificates.LOG.info(line);
              }

              @Override
              public void failed(String line) {
                LeafCertificates.LOG.warn(line);
              }
            },
            backoffMin,
            backoffMax);
  }

  void onTable(@Observes GrantTableAdopted adopted) {
    if (enabled) {
      runner.table(target(adopted.table(), application));
    }
  }

  void start(@Observes StartupEvent ignored) {
    if (!enabled) {
      return;
    }
    runner.table(target(index.current(), application));
    timer = vertx.setPeriodic(anchorsInterval.toMillis(), id -> runner.anchorsTick());
  }

  void stop(@Observes ShutdownEvent ignored) {
    if (timer >= 0) {
      vertx.cancelTimer(timer);
    }
    client.close();
  }

  /** What the check dials: the {@value #ROUTE} route's host and port, when granted to us. */
  record Target(String host, int port) {}

  static Target target(GrantIndex.Table table, String application) {
    if (table == null) {
      return null;
    }
    GrantRoute route = table.route(application, ROUTE);
    if (route == null
        || route.isPlatform()
        || !route.ssl()
        || route.targetProblem() != null
        || !route.methods().contains("CONNECT")) {
      return null;
    }
    return new Target(route.host().toLowerCase(Locale.ROOT), route.dialPort());
  }

  /**
   * The published anchors.
   *
   * @param version the bundle's version (its ETag), which moves with any anchor change
   * @param anchors every listed anchor's subject by the hex SHA-256 of its DER certificate
   */
  public record Anchors(String version, Map<String, String> anchors) {

    /** The anchors a door listing exactly {@code certificates} would publish. */
    public static Anchors of(String version, List<X509Certificate> certificates)
        throws java.security.cert.CertificateException {
      Map<String, String> anchors = new LinkedHashMap<>();
      for (X509Certificate certificate : certificates) {
        anchors.put(AnchorTrust.sha256(certificate), certificate.getSubjectX500Principal().getName());
      }
      return new Anchors(version, anchors);
    }
  }

  /**
   * One check's answer.
   *
   * @param status the status line of {@code HEAD /v1/} inside the tunnel
   * @param leafSerial the serial of the leaf the handshake was served, hex
   * @param issuer the subject of the published anchor the leaf's chain ended in
   */
  public record Outcome(int status, String leafSerial, String issuer) {}

  /** A refusal along the way, with a reason safe to log. */
  public static final class CheckFailed extends RuntimeException {
    CheckFailed(String reason) {
      super(reason, null, false, false);
    }
  }

  /** {@code GET <certificates-url>/api/anchors} as JSON: the door is public, no bearer is sent. */
  CompletionStage<Anchors> anchors() {
    return anchors(client, certificatesUrl, timeout.toMillis());
  }

  /** The anchors door, asked on {@code client}. */
  public static CompletionStage<Anchors> anchors(
      HttpClient client, String certificatesUrl, long timeoutMs) {
    String base = certificatesUrl;
    while (base.endsWith("/")) {
      base = base.substring(0, base.length() - 1);
    }
    RequestOptions options =
        new RequestOptions()
            .setMethod(HttpMethod.GET)
            .setAbsoluteURI(base + "/api/anchors")
            .setConnectTimeout(timeoutMs)
            .setTimeout(timeoutMs)
            .putHeader(HttpHeaders.ACCEPT, "application/json");
    return client
        .request(options)
        .compose(request -> request.send())
        .compose(
            response ->
                response
                    .body()
                    .map(
                        body -> {
                          if (response.statusCode() != 200) {
                            throw new CheckFailed("the anchors door answered " + response.statusCode());
                          }
                          return anchors(body.toString());
                        }))
        .toCompletionStage();
  }

  /** The anchors door's JSON: {@code {version, anchors:[{subject, sha256, ...}]}}. */
  static Anchors anchors(String body) {
    JsonObject json;
    try {
      json = new JsonObject(body);
    } catch (RuntimeException e) {
      throw new CheckFailed("the anchors answer is not JSON");
    }
    JsonArray listed = json.getJsonArray("anchors");
    Map<String, String> anchors = new LinkedHashMap<>();
    if (listed != null) {
      for (int i = 0; i < listed.size(); i++) {
        JsonObject anchor = listed.getJsonObject(i);
        String sha256 = anchor == null ? null : anchor.getString("sha256");
        if (sha256 != null && !sha256.isBlank()) {
          anchors.put(sha256.toLowerCase(Locale.ROOT), anchor.getString("subject", "-"));
        }
      }
    }
    if (anchors.isEmpty()) {
      throw new CheckFailed("no anchor is published");
    }
    return new Anchors(json.getString("version", "-"), anchors);
  }

  /** The tunnel, the handshake and the {@code HEAD}, off the event loop. */
  CompletionStage<Outcome> probe(Target target, Anchors anchors) {
    return bearer
        .token()
        .thenCompose(
            token -> {
              if (token.isEmpty()) {
                return CompletableFuture.failedFuture(
                    new CheckFailed("this process holds no qits client token"));
              }
              return vertx
                  .executeBlocking(
                      () ->
                          probe(
                              proxy.port(),
                              target.host(),
                              target.port(),
                              token.get(),
                              anchors,
                              (int) timeout.toMillis()),
                      false)
                  .toCompletionStage();
            });
  }

  /**
   * One check, blocking: {@code CONNECT host:port} on {@code 127.0.0.1:proxyPort} with the bearer,
   * a TLS handshake trusting only {@code anchors} with SNI {@code host}, {@code HEAD /v1/}.
   */
  public static Outcome probe(
      int proxyPort, String host, int port, String bearer, Anchors anchors, int timeoutMs)
      throws Exception {
    try (Socket raw = new Socket()) {
      raw.connect(new InetSocketAddress("127.0.0.1", proxyPort), timeoutMs);
      raw.setSoTimeout(timeoutMs);
      OutputStream out = raw.getOutputStream();
      String authority = host + ":" + port;
      out.write(
          ("CONNECT " + authority + " HTTP/1.1\r\nHost: " + authority
                  + "\r\nProxy-Authorization: Bearer " + bearer + "\r\n\r\n")
              .getBytes(StandardCharsets.ISO_8859_1));
      out.flush();
      int connected = status(head(raw.getInputStream()));
      if (connected != 200) {
        throw new CheckFailed("the CONNECT was answered " + connected);
      }
      AnchorTrust trust = new AnchorTrust(anchors.anchors());
      SSLContext context = SSLContext.getInstance("TLS");
      context.init(null, new TrustManager[] {trust}, null);
      try (SSLSocket tls = (SSLSocket) context.getSocketFactory().createSocket(raw, host, port, true)) {
        SSLParameters parameters = tls.getSSLParameters();
        parameters.setServerNames(List.of(new SNIHostName(host)));
        parameters.setEndpointIdentificationAlgorithm("HTTPS");
        parameters.setApplicationProtocols(new String[] {"http/1.1"});
        tls.setSSLParameters(parameters);
        try {
          tls.startHandshake();
        } catch (IOException refused) {
          throw new CheckFailed("the handshake failed: " + refused.getMessage());
        }
        X509Certificate leaf = (X509Certificate) tls.getSession().getPeerCertificates()[0];
        OutputStream inner = tls.getOutputStream();
        inner.write(
            ("HEAD " + PATH + " HTTP/1.1\r\nHost: " + (port == 443 ? host : authority)
                    + "\r\nConnection: close\r\n\r\n")
                .getBytes(StandardCharsets.ISO_8859_1));
        inner.flush();
        int status = status(head(tls.getInputStream()));
        return new Outcome(status, serial(leaf.getSerialNumber()), trust.matchedSubject());
      }
    }
  }

  static String serial(BigInteger serial) {
    return serial.toString(16);
  }

  /** A response head, read byte by byte so nothing after it is consumed. */
  static String head(InputStream in) throws IOException {
    ByteArrayOutputStream bytes = new ByteArrayOutputStream();
    int matched = 0;
    while (matched < 4) {
      int b = in.read();
      if (b < 0) {
        throw new CheckFailed("the connection closed before a response head");
      }
      bytes.write(b);
      matched = (b == "\r\n\r\n".charAt(matched)) ? matched + 1 : (b == '\r' ? 1 : 0);
      if (bytes.size() > 16_384) {
        throw new CheckFailed("the response head is too long");
      }
    }
    return bytes.toString(StandardCharsets.ISO_8859_1);
  }

  static int status(String head) {
    String[] first = head.split("\r\n", 2)[0].split(" ");
    try {
      return Integer.parseInt(first[1]);
    } catch (RuntimeException e) {
      throw new CheckFailed("not an HTTP response");
    }
  }

  /**
   * The check's schedule, apart from the wiring so a suite drives it with fakes: when to run, the
   * backoff, the anchors watch, and the two log lines.
   */
  static final class Runner {

    /** Where the two lines go. */
    interface Sink {
      void ok(String line);

      void failed(String line);
    }

    /** Runs a task later. */
    interface Scheduler {
      void after(Duration delay, Runnable task);
    }

    /** The tunnel, the handshake and the request. */
    interface Probe {
      CompletionStage<Outcome> probe(Target target, Anchors anchors);
    }

    private final Supplier<CompletionStage<Anchors>> anchors;

    private final Probe probe;

    private final Predicate<String> leafHeld;

    private final Scheduler scheduler;

    private final Sink sink;

    private final Duration backoffMin;

    private final Duration backoffMax;

    // --- guarded by this ---------------------------------------------------------------------------

    private Target target;

    /** Bumped when the target changes: a task scheduled for an older one does nothing. */
    private long generation;

    /** The anchors' version the last good check ran against, or null. */
    private String checked;

    private boolean running;

    private int failures;

    private int leafPolls;

    Runner(
        Supplier<CompletionStage<Anchors>> anchors,
        Probe probe,
        Predicate<String> leafHeld,
        Scheduler scheduler,
        Sink sink,
        Duration backoffMin,
        Duration backoffMax) {
      this.anchors = anchors;
      this.probe = probe;
      this.leafHeld = leafHeld;
      this.scheduler = scheduler;
      this.sink = sink;
      this.backoffMin = backoffMin;
      this.backoffMax = backoffMax;
    }

    /** The table in force grants {@code next} (null: no such route). Never blocks. */
    void table(Target next) {
      long scheduled;
      synchronized (this) {
        if (Objects.equals(next, target)) {
          return;
        }
        target = next;
        generation++;
        checked = null;
        failures = 0;
        leafPolls = 0;
        if (next == null) {
          return;
        }
        scheduled = generation;
      }
      scheduler.after(Duration.ZERO, () -> run(scheduled));
    }

    /** The periodic look at the anchors: a moved version checks again. Never blocks. */
    void anchorsTick() {
      long current;
      String version;
      synchronized (this) {
        if (target == null || running || checked == null) {
          return;
        }
        current = generation;
        version = checked;
      }
      CompletionStage<Anchors> read;
      try {
        read = anchors.get();
      } catch (RuntimeException e) {
        return;
      }
      read.whenComplete(
          (published, failure) -> {
            if (failure == null && published != null && !version.equals(published.version())) {
              run(current);
            }
          });
    }

    synchronized boolean ok() {
      return checked != null;
    }

    void run(long scheduledFor) {
      Target checking;
      synchronized (this) {
        if (scheduledFor != generation || running || target == null) {
          return;
        }
        checking = target;
        if (!leafHeld.test(checking.host()) && leafPolls < LEAF_POLLS) {
          leafPolls++;
          scheduler.after(LEAF_POLL, () -> run(scheduledFor));
          return;
        }
        running = true;
      }
      CompletionStage<Anchors> read;
      try {
        read = anchors.get();
      } catch (RuntimeException e) {
        read = CompletableFuture.failedFuture(e);
      }
      read.thenCompose(
              published ->
                  probe.probe(checking, published).thenApply(outcome -> Map.entry(published, outcome)))
          .whenComplete(
              (done, failure) -> finish(scheduledFor, checking, done, failure));
    }

    private void finish(
        long scheduledFor, Target checking, Map.Entry<Anchors, Outcome> done, Throwable failure) {
      Duration retryIn = null;
      synchronized (this) {
        running = false;
        if (scheduledFor != generation) {
          return;
        }
        if (failure == null && done != null) {
          checked = done.getKey().version();
          failures = 0;
          leafPolls = 0;
        } else {
          failures++;
          retryIn = backoff(failures);
        }
      }
      if (retryIn == null) {
        Outcome outcome = done.getValue();
        sink.ok(
            "egress tls self-check ok host="
                + checking.host()
                + " leafSerial="
                + outcome.leafSerial()
                + " issuer="
                + outcome.issuer()
                + " status="
                + outcome.status());
        return;
      }
      sink.failed(
          "egress tls self-check failed host="
              + checking.host()
              + " reason="
              + reason(failure)
              + " retryIn="
              + retryIn);
      scheduler.after(retryIn, () -> run(scheduledFor));
    }

    /** How long the {@code failures}-th failure in a row waits: doubling, capped. */
    Duration backoff(int failures) {
      Duration delay = backoffMin;
      for (int i = 1; i < failures && delay.compareTo(backoffMax) < 0; i++) {
        delay = delay.multipliedBy(2);
      }
      return delay.compareTo(backoffMax) > 0 ? backoffMax : delay;
    }

    static String reason(Throwable failure) {
      Throwable cause = failure;
      while ((cause instanceof CompletionException
              || cause instanceof java.util.concurrent.ExecutionException)
          && cause.getCause() != null) {
        cause = cause.getCause();
      }
      if (cause == null) {
        return "no outcome";
      }
      String message = cause.getMessage();
      String text =
          cause instanceof CheckFailed
              ? String.valueOf(message)
              : cause.getClass().getSimpleName() + (message == null ? "" : ": " + message);
      text = text.replaceAll("[\\r\\n]+", " ");
      return text.length() > 200 ? text.substring(0, 200) : text;
    }
  }
}
