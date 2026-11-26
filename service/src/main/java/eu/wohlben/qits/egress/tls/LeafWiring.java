package eu.wohlben.qits.egress.tls;

import eu.wohlben.qits.egress.grants.GrantIndex;
import eu.wohlben.qits.egress.grants.GrantTableAdopted;
import eu.wohlben.qits.egress.proxy.ClaudeHosts;
import io.quarkus.runtime.ShutdownEvent;
import io.quarkus.runtime.StartupEvent;
import io.vertx.core.Vertx;
import io.vertx.core.http.HttpClient;
import io.vertx.core.http.HttpClientOptions;
import jakarta.annotation.PostConstruct;
import jakarta.enterprise.event.Observes;
import jakarta.enterprise.inject.Instance;
import jakarta.enterprise.inject.Produces;
import jakarta.inject.Inject;
import jakarta.inject.Singleton;
import java.time.Clock;
import java.time.Duration;
import java.util.Set;
import java.util.TreeSet;
import org.eclipse.microprofile.config.inject.ConfigProperty;

/**
 * Builds this replica's {@link LeafCertificates} on {@link LeafDoor} and keeps it fed:
 *
 * <ul>
 *   <li>every {@link GrantTableAdopted} — a push taken here, a refresh that read a moved version,
 *       the table loaded at boot — hands it the table's https hosts to pre-issue for, with the
 *       Claude hosts ({@link ClaudeHosts}) always among them;
 *   <li>at startup the table already in force, should it have been adopted before this observer
 *       existed;
 *   <li>a periodic {@link LeafCertificates#tick} every {@code qits.egress.leaves.check-interval}
 *       drives renewal and the retries.
 * </ul>
 *
 * <p>Nothing here gates readiness: a replica with no leaf serves every non-intercepted call.
 */
@Singleton
public class LeafWiring {

  @Inject Vertx vertx;

  @Inject GrantIndex index;

  @Inject LeafBearer bearer;

  @Inject ClaudeHosts claude;

  /**
   * A {@link LeafIssuer} bean, when there is one: the suites' throwaway CA. A deployment has none,
   * and the leaves are issued by {@link LeafDoor} at qits-certificates.
   */
  @Inject Instance<LeafIssuer> issuers;

  @ConfigProperty(name = "qits.egress.certificates-url")
  String certificatesUrl;

  @ConfigProperty(name = "qits.egress.leaves.renew-fraction", defaultValue = "0.6667")
  double renewFraction;

  @ConfigProperty(name = "qits.egress.leaves.concurrency", defaultValue = "4")
  int concurrency;

  @ConfigProperty(name = "qits.egress.leaves.backoff-min", defaultValue = "30s")
  Duration backoffMin;

  @ConfigProperty(name = "qits.egress.leaves.backoff-max", defaultValue = "10m")
  Duration backoffMax;

  @ConfigProperty(name = "qits.egress.leaves.timeout", defaultValue = "10s")
  Duration timeout;

  @ConfigProperty(name = "qits.egress.leaves.check-interval", defaultValue = "5s")
  Duration checkInterval;

  private HttpClient client;

  private LeafCertificates leaves;

  private long timer = -1;

  @PostConstruct
  void build() {
    // A small client of its own, never the proxy's; TLS by the JVM trust store (quarkus.ssl.native).
    client = vertx.createHttpClient(new HttpClientOptions().setKeepAlive(true).setVerifyHost(true));
    LeafIssuer issuer =
        issuers.isResolvable()
            ? issuers.get()
            : new LeafDoor(vertx, client, certificatesUrl, bearer::token, timeout.toMillis());
    leaves =
        new LeafCertificates(
            issuer,
            Clock.systemUTC(),
            new LeafCertificates.Settings(
                renewFraction, concurrency, backoffMin, backoffMax, timeout));
  }

  /** This replica's leaves, for the interception listener (qits-2644) and its self-check. */
  @Produces
  @Singleton
  LeafCertificates leafCertificates() {
    return leaves;
  }

  void onTable(@Observes GrantTableAdopted adopted) {
    leaves.want(wanted(adopted.table()));
  }

  void start(@Observes StartupEvent ignored) {
    leaves.want(wanted(index.current()));
    timer = vertx.setPeriodic(checkInterval.toMillis(), id -> leaves.tick());
  }

  /**
   * The hosts to hold leaves for: the table's https hosts, and the Claude hosts (qits-2664), whose
   * {@code CONNECT} is intercepted whatever the table says.
   */
  private Set<String> wanted(GrantIndex.Table table) {
    Set<String> hosts = new TreeSet<>(claude.hosts());
    if (table != null) {
      hosts.addAll(LeafCertificates.httpsHosts(table));
    }
    return hosts;
  }

  void stop(@Observes ShutdownEvent ignored) {
    if (timer >= 0) {
      vertx.cancelTimer(timer);
    }
    if (client != null) {
      client.close();
    }
  }
}
