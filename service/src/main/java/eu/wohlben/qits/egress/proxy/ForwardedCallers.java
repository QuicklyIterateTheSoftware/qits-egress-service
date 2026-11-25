package eu.wohlben.qits.egress.proxy;

import eu.wohlben.qits.egress.identity.CallerIdentity;
import io.vertx.core.http.HttpConnection;
import io.vertx.core.net.SocketAddress;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

/**
 * <b>Who a forward carries</b> (epic qits-2525, qits-2654): the callers of {@code GET
 * /egress/api/forward}, by the loopback port their splice to the proxy listener comes from.
 *
 * <p>A container that cannot reach the wire alias opens a websocket at the edge-routed door ({@link
 * ForwardDoor}); this process dials its own proxy listener on {@code 127.0.0.1}, records here who
 * opened the websocket — keyed by that connection's LOCAL port, which is the remote port the
 * listener sees — and splices the two. {@link EgressProxy} then takes a request on that connection
 * without {@code Proxy-Authorization} (or, in the gateway form, without {@code Authorization}) as
 * the forward's caller. Modelled on {@link Interception}, whose tunnels are keyed the same way.
 *
 * <p>The entry is removed when the splice closes. Only a connection from a loopback address is
 * looked up: the proxy listener is bound to every interface, and a peer on qits-net whose source
 * port happens to match must never be taken for a forward's caller.
 */
final class ForwardedCallers {

  /**
   * One forward's caller.
   *
   * @param verdict the caller, as the upgrade's {@code Authorization: Bearer} identified it
   * @param bearer the bearer it presented: a platform route exchanges it, nothing else reads it.
   *     Never printed ({@link #toString}).
   */
  record Forward(CallerIdentity.Verdict verdict, String bearer) {

    @Override
    public String toString() {
      return "Forward[" + verdict.principal() + "]";
    }
  }

  private final Map<Integer, Forward> byPort = new ConcurrentHashMap<>();

  /** A loopback connection, opened from {@code localPort}, now carries {@code forward}. */
  void register(int localPort, Forward forward) {
    byPort.put(localPort, forward);
  }

  /** The loopback connection from {@code localPort} closed. */
  void release(int localPort, Forward forward) {
    byPort.remove(localPort, forward);
  }

  /** The forward a loopback connection from {@code remotePort} carries, or null. */
  Forward at(int remotePort) {
    return byPort.get(remotePort);
  }

  /**
   * The forward a proxy-listener connection carries: one from a loopback address whose port is
   * registered, else null.
   */
  Forward of(HttpConnection connection) {
    if (connection == null) {
      return null;
    }
    SocketAddress remote = connection.remoteAddress();
    if (remote == null || !loopback(remote.hostAddress())) {
      return null;
    }
    return at(remote.port());
  }

  /** How many forwards are open. */
  int open() {
    return byPort.size();
  }

  /** Whether an address, as Vert.x prints it, is this host's own loopback. */
  static boolean loopback(String address) {
    if (address == null) {
      return false;
    }
    return address.equals("127.0.0.1")
        || address.equals("::1")
        || address.equals("0:0:0:0:0:0:0:1")
        || address.equals("::ffff:127.0.0.1");
  }
}
