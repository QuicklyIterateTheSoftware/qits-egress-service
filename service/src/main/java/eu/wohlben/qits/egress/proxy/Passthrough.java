package eu.wohlben.qits.egress.proxy;

import eu.wohlben.qits.egress.identity.Principal;
import io.netty.util.NetUtil;
import io.vertx.core.Future;
import io.vertx.core.Vertx;
import io.vertx.core.net.SocketAddress;
import jakarta.enterprise.context.ApplicationScoped;
import jakarta.enterprise.inject.Instance;
import jakarta.inject.Inject;
import java.net.Inet4Address;
import java.net.Inet6Address;
import java.net.InetAddress;
import java.net.UnknownHostException;
import java.util.List;
import java.util.Locale;
import org.eclipse.microprofile.config.inject.ConfigProperty;

/**
 * <b>Outside hosts without a grant</b> (epic qits-2525, qits-2654): what a principal with a project
 * — {@code project:}, or an {@code agent:} that carries its project — may reach when no granted
 * route matches. An application never gets it.
 *
 * <ul>
 *   <li>{@code CONNECT host:port}, the port in {@code qits.egress.passthrough.connect-ports} (443):
 *       a BLIND splice — no interception, no injection ({@link ConnectTunnel#blind}).
 *   <li>Absolute-form {@code http://host[:port]/…}, the port in {@code
 *       qits.egress.passthrough.http-ports} (80): forwarded as it is, the caller's own {@code
 *       Authorization} and {@code Cookie} kept; only {@code Proxy-Authorization} and the hop-by-hop
 *       set go ({@link PassthroughOutbound}).
 * </ul>
 *
 * <p>Refused, {@code 403 {"error":"passthrough refused","reason":…}}, audit reason {@code
 * passthrough-<reason>}: {@code port} (any other port), {@code platform-host} ({@code
 * qits.${QITS_DOMAIN}} and every name under it), {@code single-label} (a name without a dot, such
 * as a wire alias) and {@code private-address} (the name resolves to ANY non-public address, {@link
 * #isPublic}). A name that does not resolve at all is {@code 502}, reason {@code
 * passthrough-unresolved}.
 *
 * <p><b>Resolved once, every address checked, the checked address dialled</b> — never the name
 * again — so a DNS answer that changes between the check and the dial (rebinding) cannot reach
 * qits-net, where this process sits beside every platform service.
 */
@ApplicationScoped
public class Passthrough {

  /** A refusal's reason, as the body and the audit line ({@code passthrough-<reason>}) name it. */
  static final String PORT = "port";

  static final String PLATFORM_HOST = "platform-host";

  static final String SINGLE_LABEL = "single-label";

  static final String PRIVATE_ADDRESS = "private-address";

  static final String UNRESOLVED = "unresolved";

  @Inject Vertx vertx;

  @Inject Instance<PassthroughNetwork> networks;

  @ConfigProperty(name = "qits.egress.passthrough.enabled", defaultValue = "true")
  boolean enabled;

  @ConfigProperty(name = "qits.egress.passthrough.connect-ports", defaultValue = "443")
  List<Integer> connectPorts;

  @ConfigProperty(name = "qits.egress.passthrough.http-ports", defaultValue = "80")
  List<Integer> httpPorts;

  /** The platform's own names: this one and every name under it are refused. */
  @ConfigProperty(name = "qits.egress.passthrough.platform-domain")
  String platformDomain;

  /**
   * Where a checked name goes: its one checked address, dialled.
   *
   * @param address the address every check passed for — the first the name resolved to
   * @param dial where it is dialled ({@link PassthroughNetwork#dial})
   */
  record Checked(InetAddress address, SocketAddress dial) {}

  /** The outcome of a check: where to dial, or why not. */
  record Outcome(Checked checked, String refusal) {

    static Outcome refused(String reason) {
      return new Outcome(null, reason);
    }
  }

  /** Whether {@code principal} gets the passthrough at all: on, and it has a project. */
  boolean applies(Principal principal) {
    return enabled
        && principal != null
        && principal.application() == null
        && principal.project() != null;
  }

  /** Whether {@code port} may be tunnelled blind. */
  boolean connectPort(int port) {
    return connectPorts.contains(port);
  }

  /** Whether {@code port} may be forwarded as plain http. */
  boolean httpPort(int port) {
    return httpPorts.contains(port);
  }

  /**
   * Check {@code host} for {@code port}, which the caller has checked against its form's ports:
   * the name's own refusals first, then resolved once, every address checked. Never a failed
   * future.
   */
  Future<Outcome> check(String host, int port) {
    String name = nameRefusal(host, platformDomain);
    if (name != null) {
      return Future.succeededFuture(Outcome.refused(name));
    }
    PassthroughNetwork network = network();
    InetAddress literal = literal(host);
    if (literal != null) {
      return Future.succeededFuture(outcome(List.of(literal), network, port));
    }
    return vertx
        .<List<InetAddress>>executeBlocking(() -> network.resolve(host), false)
        .map(addresses -> outcome(addresses, network, port))
        .otherwise(failure -> Outcome.refused(UNRESOLVED));
  }

  private PassthroughNetwork network() {
    return networks.isResolvable() ? networks.get() : PassthroughNetwork.SYSTEM;
  }

  private static Outcome outcome(List<InetAddress> addresses, PassthroughNetwork network, int port) {
    if (addresses == null || addresses.isEmpty()) {
      return Outcome.refused(UNRESOLVED);
    }
    for (InetAddress address : addresses) {
      if (!isPublic(address)) {
        return Outcome.refused(PRIVATE_ADDRESS);
      }
    }
    InetAddress checked = addresses.get(0);
    return new Outcome(new Checked(checked, network.dial(checked, port)), null);
  }

  /**
   * The refusal a name earns before it is resolved, or null: {@code platform-host} for {@code
   * <platformDomain>} and below, {@code single-label} for a name without a dot. An IP literal is
   * neither; its address is checked like a resolved one. Pure, for the tests.
   */
  static String nameRefusal(String host, String platformDomain) {
    String name = host.toLowerCase(Locale.ROOT);
    while (name.endsWith(".")) {
      name = name.substring(0, name.length() - 1);
    }
    if (literal(name) != null) {
      return null;
    }
    String platform = platformDomain == null ? "" : platformDomain.toLowerCase(Locale.ROOT);
    if (!platform.isEmpty() && (name.equals(platform) || name.endsWith("." + platform))) {
      return PLATFORM_HOST;
    }
    if (name.isEmpty() || name.indexOf('.') < 0) {
      return SINGLE_LABEL;
    }
    return null;
  }

  /** An IP literal as an address, without a lookup, or null when the host is a name. */
  static InetAddress literal(String host) {
    byte[] bytes = NetUtil.createByteArrayFromIpAddressString(host);
    if (bytes == null) {
      return null;
    }
    try {
      return InetAddress.getByAddress(bytes);
    } catch (UnknownHostException impossible) {
      return null;
    }
  }

  /**
   * Whether an address is on the public internet: not loopback, {@code 0.0.0.0/8}, {@code 10/8},
   * {@code 172.16/12}, {@code 192.168/16}, {@code 169.254/16}, {@code 100.64/10}, {@code 240/4}
   * (reserved and broadcast), multicast, {@code ::}, {@code ::1}, {@code fc00::/7} or {@code
   * fe80::/10}. An IPv4-mapped IPv6 address is judged by its IPv4 address (Java hands those over as
   * {@link Inet4Address} already); so is NAT64's {@code 64:ff9b::/96}.
   */
  static boolean isPublic(InetAddress address) {
    if (address.isAnyLocalAddress()
        || address.isLoopbackAddress()
        || address.isLinkLocalAddress()
        || address.isSiteLocalAddress()
        || address.isMulticastAddress()) {
      return false;
    }
    byte[] b = address.getAddress();
    if (address instanceof Inet4Address) {
      return publicV4(b);
    }
    if (address instanceof Inet6Address) {
      int first = b[0] & 0xff;
      if ((first & 0xfe) == 0xfc) {
        return false; // fc00::/7
      }
      if (first == 0xfe && (b[1] & 0xc0) == 0x80) {
        return false; // fe80::/10
      }
      if (first == 0xfe && (b[1] & 0xc0) == 0xc0) {
        return false; // fec0::/10, the old site-local
      }
      if (nat64(b) || compatible(b)) {
        return publicV4(new byte[] {b[12], b[13], b[14], b[15]});
      }
      return true;
    }
    return false;
  }

  private static boolean publicV4(byte[] b) {
    int a0 = b[0] & 0xff;
    int a1 = b[1] & 0xff;
    if (a0 == 0 || a0 == 10 || a0 == 127) {
      return false;
    }
    if (a0 == 172 && a1 >= 16 && a1 <= 31) {
      return false;
    }
    if (a0 == 192 && a1 == 168) {
      return false;
    }
    if (a0 == 169 && a1 == 254) {
      return false;
    }
    if (a0 == 100 && a1 >= 64 && a1 <= 127) {
      return false;
    }
    return a0 < 224; // multicast 224/4, reserved 240/4 and the broadcast address
  }

  /** {@code 64:ff9b::/96}: NAT64, an IPv4 address in the last four bytes. */
  private static boolean nat64(byte[] b) {
    if ((b[0] & 0xff) != 0x00 || (b[1] & 0xff) != 0x64 || (b[2] & 0xff) != 0xff || (b[3] & 0xff) != 0x9b) {
      return false;
    }
    for (int i = 4; i < 12; i++) {
      if (b[i] != 0) {
        return false;
      }
    }
    return true;
  }

  /** {@code ::a.b.c.d}, the deprecated IPv4-compatible form ({@code ::} and {@code ::1} excluded above). */
  private static boolean compatible(byte[] b) {
    for (int i = 0; i < 12; i++) {
      if (b[i] != 0) {
        return false;
      }
    }
    return true;
  }
}
