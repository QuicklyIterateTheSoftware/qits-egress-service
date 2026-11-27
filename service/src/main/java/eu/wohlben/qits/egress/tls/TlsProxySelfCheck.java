package eu.wohlben.qits.egress.tls;

import eu.wohlben.qits.egress.proxy.TlsProxyListening;
import io.quarkus.runtime.ShutdownEvent;
import io.vertx.core.Vertx;
import io.vertx.core.json.JsonObject;
import jakarta.enterprise.event.Observes;
import jakarta.inject.Inject;
import jakarta.inject.Singleton;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.security.cert.X509Certificate;
import java.time.Duration;
import java.util.List;
import javax.net.ssl.SNIHostName;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLParameters;
import javax.net.ssl.SSLSocket;
import org.eclipse.microprofile.config.inject.ConfigProperty;

/**
 * <b>The live proof of the TLS proxy listener</b> (epic qits-2626, qits-2759): once 8082 opens, and
 * every {@code qits.egress.tls-proxy.self-check.interval} (1 h) after, the egress dials its own
 * 8082 on loopback as a client of itself:
 *
 * <ol>
 *   <li>its own workload certificate as the client certificate, the platform anchors as the only
 *       trust, the host name checked against the wire alias {@code <env>-qits-egress} (SNI too) —
 *       so the server certificate must be a platform one naming the alias;
 *   <li>{@code GET /}{@value #ROUTE}{@code /} with no bearer, a route nobody holds: the listener
 *       answers 403 {@code no grant} naming the principal the certificate decided, which must be
 *       {@code application:qits-egress}.
 * </ol>
 *
 * <p>One line on logger {@code eu.wohlben.qits.egress.tls}: INFO {@code egress tls-proxy self-check
 * ok principal=<p> serverSerial=<hex> clientSerial=<hex>}, or WARN {@code egress tls-proxy
 * self-check failed reason=<r> retryIn=<d>}; a failure tries again after {@code retry} (1 min).
 * Never part of readiness. Off in {@code %test}; the suite calls {@link #probe} itself.
 */
@Singleton
public class TlsProxySelfCheck {

  /** The route the probe asks for: held by nobody, so the answer names the caller. */
  public static final String ROUTE = "tls-proxy-self-check";

  @Inject Vertx vertx;

  @Inject TlsProxyWiring wiring;

  @ConfigProperty(name = "quarkus.application.name", defaultValue = "qits-egress")
  String application;

  @ConfigProperty(name = "qits.egress.environment")
  String environment;

  @ConfigProperty(name = "qits.egress.tls-proxy.self-check.enabled", defaultValue = "true")
  boolean enabled;

  @ConfigProperty(name = "qits.egress.tls-proxy.self-check.interval", defaultValue = "1h")
  Duration interval;

  @ConfigProperty(name = "qits.egress.tls-proxy.self-check.retry", defaultValue = "1m")
  Duration retry;

  @ConfigProperty(name = "qits.egress.leaves.timeout", defaultValue = "10s")
  Duration timeout;

  private volatile boolean stopped;

  /** What the probe saw. */
  public record Outcome(String principal, String serverSerial, String clientSerial) {}

  void onListening(@Observes TlsProxyListening listening) {
    if (enabled) {
      schedule(listening.port(), Duration.ZERO);
    }
  }

  void stop(@Observes ShutdownEvent ignored) {
    stopped = true;
  }

  private void schedule(int port, Duration delay) {
    if (stopped) {
      return;
    }
    vertx.setTimer(
        Math.max(1, delay.toMillis()),
        id ->
            vertx
                .<Outcome>executeBlocking(
                    () ->
                        probe(
                            wiring.tls().clientContext(),
                            port,
                            environment + "-" + application,
                            (int) timeout.toMillis()),
                    false)
                .onComplete(
                    result -> {
                      String expected = "application:" + application;
                      if (result.succeeded() && expected.equals(result.result().principal())) {
                        LeafCertificates.LOG.infof(
                            "egress tls-proxy self-check ok principal=%s serverSerial=%s"
                                + " clientSerial=%s",
                            result.result().principal(),
                            result.result().serverSerial(),
                            result.result().clientSerial());
                        schedule(port, interval);
                        return;
                      }
                      String reason =
                          result.succeeded()
                              ? "the listener named " + result.result().principal()
                                  + ", not " + expected
                              : TlsSelfCheck.Runner.reason(result.cause());
                      LeafCertificates.LOG.warnf(
                          "egress tls-proxy self-check failed reason=%s retryIn=%s", reason, retry);
                      schedule(port, retry);
                    }));
  }

  /**
   * Dial 8082 on loopback with {@code context} (a client certificate, the anchors as trust), the
   * host name checked as {@code alias}, and read whom the listener took the caller for. Blocking.
   */
  public static Outcome probe(SSLContext context, int port, String alias, int timeoutMs)
      throws Exception {
    try (Socket raw = new Socket()) {
      raw.connect(new InetSocketAddress("127.0.0.1", port), timeoutMs);
      raw.setSoTimeout(timeoutMs);
      try (SSLSocket tls =
          (SSLSocket) context.getSocketFactory().createSocket(raw, alias, port, true)) {
        SSLParameters parameters = tls.getSSLParameters();
        parameters.setServerNames(List.of(new SNIHostName(alias)));
        parameters.setEndpointIdentificationAlgorithm("HTTPS");
        parameters.setApplicationProtocols(new String[] {"http/1.1"});
        tls.setSSLParameters(parameters);
        try {
          tls.startHandshake();
        } catch (IOException refused) {
          throw new TlsSelfCheck.CheckFailed("the handshake failed: " + refused.getMessage());
        }
        X509Certificate server = (X509Certificate) tls.getSession().getPeerCertificates()[0];
        java.security.cert.Certificate[] local = tls.getSession().getLocalCertificates();
        String clientSerial =
            local == null || local.length == 0
                ? null
                : ((X509Certificate) local[0]).getSerialNumber().toString(16);
        OutputStream out = tls.getOutputStream();
        out.write(
            ("GET /" + ROUTE + "/ HTTP/1.1\r\nHost: " + alias + ":" + port
                    + "\r\nAccept: application/json\r\nConnection: close\r\n\r\n")
                .getBytes(StandardCharsets.ISO_8859_1));
        out.flush();
        InputStream in = tls.getInputStream();
        int status = TlsSelfCheck.status(TlsSelfCheck.head(in));
        String body = new String(in.readNBytes(16_384), StandardCharsets.UTF_8);
        if (status != 403) {
          throw new TlsSelfCheck.CheckFailed("the listener answered " + status);
        }
        int start = body.indexOf('{');
        String principal;
        try {
          principal = new JsonObject(start < 0 ? body : body.substring(start)).getString("principal");
        } catch (RuntimeException e) {
          throw new TlsSelfCheck.CheckFailed("the 403 carries no principal");
        }
        return new Outcome(
            principal, server.getSerialNumber().toString(16), clientSerial);
      }
    }
  }
}
