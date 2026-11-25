package eu.wohlben.qits.egress.proxy;

import io.vertx.core.net.SocketAddress;
import java.net.InetAddress;
import java.net.UnknownHostException;
import java.util.List;

/**
 * Where a passthrough's name resolves and where its checked address is dialled ({@link
 * Passthrough}). A deployment uses {@link #SYSTEM}: the JVM's resolver, and the checked address
 * itself. A {@code PassthroughNetwork} bean replaces it — the suites' {@code
 * SuitePassthroughNetwork}, which resolves made-up names to the addresses a test needs and dials a
 * "public" one on loopback.
 */
public interface PassthroughNetwork {

  /** Every address {@code host} resolves to. Blocking; never called on an event loop. */
  List<InetAddress> resolve(String host) throws UnknownHostException;

  /** Where the checked {@code address} is dialled for {@code port}. */
  SocketAddress dial(InetAddress address, int port);

  /** The JVM's resolver, and the checked address itself. */
  PassthroughNetwork SYSTEM =
      new PassthroughNetwork() {
        @Override
        public List<InetAddress> resolve(String host) throws UnknownHostException {
          return List.of(InetAddress.getAllByName(host));
        }

        @Override
        public SocketAddress dial(InetAddress address, int port) {
          return SocketAddress.inetSocketAddress(port, address.getHostAddress());
        }
      };
}
