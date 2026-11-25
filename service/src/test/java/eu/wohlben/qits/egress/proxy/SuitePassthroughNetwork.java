package eu.wohlben.qits.egress.proxy;

import io.vertx.core.net.SocketAddress;
import jakarta.inject.Singleton;
import java.net.InetAddress;
import java.net.UnknownHostException;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

/**
 * The suites' {@link PassthroughNetwork}, in every {@code @QuarkusTest} ({@link Passthrough} takes a
 * {@code PassthroughNetwork} bean over the JVM's resolver): a name in {@link #NAMES} resolves to the
 * addresses listed there, and a checked {@code address:port} in {@link #DIALS} is dialled where it
 * says — so a made-up "public" address reaches a fake upstream on loopback, while the check still
 * sees the public address. Anything else is the JVM's own.
 */
@Singleton
public class SuitePassthroughNetwork implements PassthroughNetwork {

  /** Made-up names and the IP literals they resolve to. */
  public static final Map<String, List<String>> NAMES = new ConcurrentHashMap<>();

  /** {@code <address>:<port>} of a checked address, and where it is really dialled. */
  public static final Map<String, SocketAddress> DIALS = new ConcurrentHashMap<>();

  @Override
  public List<InetAddress> resolve(String host) throws UnknownHostException {
    List<String> listed = NAMES.get(host);
    if (listed == null) {
      return SYSTEM.resolve(host);
    }
    List<InetAddress> addresses = new ArrayList<>();
    for (String literal : listed) {
      addresses.add(InetAddress.getByName(literal));
    }
    return addresses;
  }

  @Override
  public SocketAddress dial(InetAddress address, int port) {
    SocketAddress redirected = DIALS.get(address.getHostAddress() + ":" + port);
    return redirected != null ? redirected : SYSTEM.dial(address, port);
  }
}
