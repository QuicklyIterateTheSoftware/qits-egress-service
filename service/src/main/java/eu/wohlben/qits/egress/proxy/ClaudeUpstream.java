package eu.wohlben.qits.egress.proxy;

import io.vertx.core.net.HostAndPort;

/**
 * Where a Claude host's requests are dialled ({@link ClaudeHosts}). A deployment uses {@link
 * #SYSTEM}: the host itself on 443. A {@code ClaudeUpstream} bean replaces it — the suites' {@code
 * SuiteClaudeUpstream}, which dials a fake upstream on loopback while the request still names the
 * Claude host in its {@code Host} header.
 */
public interface ClaudeUpstream {

  /** The host name and port dialled (and verified by TLS) for {@code host}. */
  HostAndPort dial(String host);

  /** The host itself, on 443. */
  ClaudeUpstream SYSTEM = host -> HostAndPort.create(host, ClaudeHosts.PORT);
}
