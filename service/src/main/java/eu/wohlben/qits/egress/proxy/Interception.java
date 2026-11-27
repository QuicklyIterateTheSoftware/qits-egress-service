package eu.wohlben.qits.egress.proxy;

import eu.wohlben.qits.egress.identity.CallerIdentity;
import eu.wohlben.qits.egress.tls.LeafCertificates;
import eu.wohlben.qits.egress.tls.SniKeyManager;
import io.vertx.core.http.HttpConnection;
import io.vertx.core.http.HttpServerOptions;
import io.vertx.core.http.HttpVersion;
import io.vertx.core.net.JdkSSLEngineOptions;
import io.vertx.core.net.KeyCertOptions;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

/**
 * <b>TLS ended inside a {@code CONNECT} tunnel</b> (epic qits-2524, qits-2644): the loopback
 * listener's options and the tunnels it serves.
 *
 * <p>A granted {@code CONNECT} is not spliced to its target any more. {@link ConnectTunnel} opens a
 * loopback connection to this listener ({@code 127.0.0.1:qits.egress.tls.port}, 8443, bound to
 * loopback only), records here who asked and for which {@code host:port} — keyed by that
 * connection's LOCAL port, which is the remote port the listener sees — answers {@code 200} and
 * splices the caller to it. The caller's TLS handshake then ends here, with the host's leaf picked by
 * SNI ({@link SniKeyManager}), and every request inside is an ordinary HTTP request that {@link
 * EgressProxy} serves like an absolute-form one for {@code https://<SNI host>:<CONNECT port>}.
 *
 * <p>The entry is removed when the splice closes. A loopback connection with no entry (anything
 * else on this host dialling the port) is refused.
 */
final class Interception {

  /**
   * One intercepted tunnel: who opened it, and the {@code CONNECT}'s target.
   *
   * @param verdict the caller, as the {@code CONNECT}'s {@code Proxy-Authorization} identified it
   * @param authority the {@code CONNECT}'s {@code host:port}
   * @param route the route that granted the {@code CONNECT}
   * @param forwarded whether the {@code CONNECT} came over a forward ({@link ForwardedCallers}):
   *     every request inside is audited {@code via=forward} too
   * @param auth how the TLS proxy listener identified the {@code CONNECT}'s caller (qits-2759), or
   *     null on 8081: every request inside is audited with it too
   */
  record Tunnel(
      CallerIdentity.Verdict verdict,
      ConnectTunnel.Authority authority,
      String route,
      boolean forwarded,
      AuditLine.Auth auth) {}

  private final Map<Integer, Tunnel> byPort = new ConcurrentHashMap<>();

  /**
   * The listener's options: TLS with the leaf picked per handshake by SNI, HTTP/1.1 only (ALPN
   * offers nothing else), the JDK's own {@code SSLEngine}.
   *
   * <p>Vert.x' SNI switch stays OFF on purpose: on, Vert.x builds and caches one {@code SslContext}
   * per server name, and a renewed leaf would never be served. {@link SniKeyManager} reads the
   * requested name from the handshake itself.
   */
  static HttpServerOptions options(String host, int port, LeafCertificates leaves) {
    return new HttpServerOptions()
        .setHost(host)
        .setPort(port)
        .setSsl(true)
        .setSni(false)
        .setKeyCertOptions(KeyCertOptions.wrap(new SniKeyManager(leaves)))
        .setSslEngineOptions(new JdkSSLEngineOptions())
        .setUseAlpn(true)
        .setAlpnVersions(List.of(HttpVersion.HTTP_1_1))
        .setHttp2ClearTextEnabled(false);
  }

  /** A loopback connection, opened from {@code localPort}, now carries {@code tunnel}. */
  void register(int localPort, Tunnel tunnel) {
    byPort.put(localPort, tunnel);
  }

  /** The loopback connection from {@code localPort} closed. */
  void release(int localPort, Tunnel tunnel) {
    byPort.remove(localPort, tunnel);
  }

  /** The tunnel a loopback connection from {@code remotePort} carries, or null. */
  Tunnel at(int remotePort) {
    return byPort.get(remotePort);
  }

  /** How many tunnels are open. */
  int open() {
    return byPort.size();
  }

  /** The name the connection's TLS handshake asked for (SNI), lower case, or null. */
  static String sniHost(HttpConnection connection) {
    if (connection == null || !connection.isSsl()) {
      return null;
    }
    return SniKeyManager.requestedHost(connection.sslSession());
  }

  /**
   * Whether an inner request's {@code Host} names the tunnel's host: its host part equal to the
   * SNI host, and its port, when it says one, the {@code CONNECT}'s. A request without a {@code
   * Host} is taken as for the SNI host.
   */
  static boolean hostMatches(String hostHeader, String sniHost, int port) {
    if (hostHeader == null || hostHeader.isBlank()) {
      return true;
    }
    String host = hostHeader.trim();
    String portPart = null;
    if (host.startsWith("[")) {
      int close = host.indexOf(']');
      if (close < 0) {
        return false;
      }
      portPart = close + 1 < host.length() && host.charAt(close + 1) == ':' ? host.substring(close + 2) : null;
      host = host.substring(1, close);
    } else {
      int colon = host.lastIndexOf(':');
      if (colon >= 0) {
        portPart = host.substring(colon + 1);
        host = host.substring(0, colon);
      }
    }
    if (!host.toLowerCase(Locale.ROOT).equals(sniHost)) {
      return false;
    }
    if (portPart == null || portPart.isEmpty()) {
      return true;
    }
    try {
      return Integer.parseInt(portPart) == port;
    } catch (NumberFormatException notAPort) {
      return false;
    }
  }
}
