package eu.wohlben.qits.egress.proxy;

import io.vertx.core.net.HostAndPort;
import jakarta.inject.Singleton;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

/**
 * The suites' {@link ClaudeUpstream}, in every {@code @QuarkusTest} ({@link ClaudeHosts} takes a
 * {@code ClaudeUpstream} bean over {@link ClaudeUpstream#SYSTEM}): a Claude host listed in {@link
 * #DIALS} is dialled there — a fake https upstream on {@code localhost}, its certificate for {@code
 * localhost} — while the request still names the Claude host in {@code Host}. Anything else is the
 * host itself on 443.
 */
@Singleton
public class SuiteClaudeUpstream implements ClaudeUpstream {

  /** A Claude host and where it is really dialled. */
  public static final Map<String, HostAndPort> DIALS = new ConcurrentHashMap<>();

  @Override
  public HostAndPort dial(String host) {
    HostAndPort redirected = DIALS.get(host);
    return redirected != null ? redirected : SYSTEM.dial(host);
  }
}
