package eu.wohlben.qits.egress.proxy;

import java.util.Locale;

/**
 * An upstream origin as the proxy client pools it: {@code host:port}, the host lower-cased. The key
 * {@link UpstreamPools} counts by — qits-edge's {@code Upstream}, reduced to the address.
 *
 * @param host the host as dialled (a name, or a literal)
 * @param port the port as dialled
 */
record UpstreamOrigin(String host, int port) {

  UpstreamOrigin {
    if (host == null || host.isBlank() || port <= 0 || port > 65_535) {
      throw new IllegalArgumentException("not an origin: " + host + ":" + port);
    }
    host = host.toLowerCase(Locale.ROOT);
  }

  @Override
  public String toString() {
    return host + ":" + port;
  }
}
