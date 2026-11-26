package eu.wohlben.qits.egress.proxy;

import io.quarkus.runtime.annotations.RegisterForReflection;
import io.quarkus.vertx.http.runtime.filters.QuarkusRequestWrapper;
import io.vertx.core.http.HttpServerRequest;
import java.lang.reflect.Method;
import java.util.concurrent.atomic.AtomicBoolean;
import org.jboss.logging.Logger;

/**
 * <b>Tell Quarkus' HTTP drain that a forward is over, since Vert.x never will</b> — copied from
 * qits-edge's {@code DrainCount} (qits-1170), its {@code settle} only.
 *
 * <p>{@code GracefulShutdownFilter} counts every request on 8080 up as it arrives and down when its
 * {@code QuarkusRequestWrapper} runs its done handlers, which it does only from the response's end,
 * close or exception handler. A {@link ForwardDoor} forward is upgraded with {@code toWebSocket()}:
 * the HTTP response is handed to the websocket and none of those handlers ever runs, so every
 * forward ever opened stayed counted for the rest of the process's life and a shutdown waited out
 * its whole {@code quarkus.shutdown.timeout} (5 minutes) — found by a test profile switch after
 * {@code ForwardDoorTest} (qits-2660). {@link ForwardDoor} settles each forward when it closes, and
 * when its upgrade fails.
 *
 * <p><b>Why reflection.</b> {@code QuarkusRequestWrapper.done()} is package-private and the only way
 * to run the done handlers; it is idempotent (a compare-and-set on its own flag), so settling an
 * exchange whose handlers did run changes nothing. Registered for native reflection here; a release
 * that renames it costs one WARN and the old timeout, never a failed request.
 */
@RegisterForReflection(targets = QuarkusRequestWrapper.class, methods = true, fields = false)
final class DrainCount {

  private static final Logger LOG = Logger.getLogger(DrainCount.class);

  /** Before {@link #DONE}, whose initialiser may already warn. */
  private static final AtomicBoolean WARNED = new AtomicBoolean();

  private static final Method DONE = done();

  private DrainCount() {}

  /**
   * Counts this exchange as finished in Quarkus' HTTP drain. Safe more than once, on an exchange
   * already settled, and on a request Quarkus never wrapped, where it does nothing.
   */
  static void settle(HttpServerRequest request) {
    if (DONE == null) {
      return;
    }
    QuarkusRequestWrapper wrapper;
    try {
      wrapper = QuarkusRequestWrapper.get(request);
    } catch (RuntimeException notWrapped) {
      return;
    }
    if (wrapper == null) {
      return;
    }
    try {
      DONE.invoke(wrapper);
    } catch (ReflectiveOperationException | RuntimeException failure) {
      warnOnce(failure);
    }
  }

  private static Method done() {
    try {
      Method done = QuarkusRequestWrapper.class.getDeclaredMethod("done");
      done.setAccessible(true);
      return done;
    } catch (ReflectiveOperationException | RuntimeException failure) {
      warnOnce(failure);
      return null;
    }
  }

  private static void warnOnce(Throwable failure) {
    if (WARNED.compareAndSet(false, true)) {
      LOG.warnf(
          "cannot settle an upgraded forward in Quarkus' HTTP drain (%s): a shutdown will wait out"
              + " quarkus.shutdown.timeout",
          failure);
    }
  }
}
