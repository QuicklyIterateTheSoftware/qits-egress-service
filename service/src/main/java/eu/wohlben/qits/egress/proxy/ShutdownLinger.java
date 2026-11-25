package eu.wohlben.qits.egress.proxy;

import io.quarkus.runtime.ShutdownEvent;
import jakarta.annotation.Priority;
import jakarta.enterprise.context.ApplicationScoped;
import jakarta.enterprise.event.Observes;
import java.time.Duration;
import org.eclipse.microprofile.config.inject.ConfigProperty;
import org.jboss.logging.Logger;

/**
 * <b>The drain is over; stay alive a moment longer</b>, so the kernel can send what the last
 * responses handed it. Copied from qits-edge (qits-1170), where a 201 MB download lost its last
 * 639,236 bytes to a process that exited the instant its last response was "written" — into the
 * send buffer, not onto the client — and swarm tore the network namespace down under it.
 *
 * <p>Observes {@link ShutdownEvent} at the latest priority, so it runs after {@link
 * EgressProxy#draining}, which drains the proxy listener at the default priority of the same
 * event, and after every other observer's cleanup. Vert.x is closed only after these observers, so
 * its event loops keep flushing during the linger.
 */
@ApplicationScoped
public class ShutdownLinger {

  private static final Logger LOG = Logger.getLogger(ShutdownLinger.class);

  @ConfigProperty(name = "qits.egress.shutdown.linger", defaultValue = "10s")
  Duration linger;

  void lingering(@Observes @Priority(Integer.MAX_VALUE) ShutdownEvent event) {
    linger(linger);
  }

  /** Sleeps {@code linger} on the calling thread; zero or negative returns at once. */
  static void linger(Duration linger) {
    if (linger.isZero() || linger.isNegative()) {
      LOG.debug("shutting down: no linger configured");
      return;
    }
    LOG.infof(
        "shutting down: lingering %dms so the kernel can flush what the last responses sent",
        linger.toMillis());
    try {
      Thread.sleep(linger.toMillis());
    } catch (InterruptedException e) {
      Thread.currentThread().interrupt();
    }
  }
}
