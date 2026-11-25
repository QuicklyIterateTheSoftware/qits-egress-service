package eu.wohlben.qits.egress.tls;

import java.net.Socket;
import java.security.Principal;
import java.security.PrivateKey;
import java.security.cert.X509Certificate;
import java.time.Instant;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.ConcurrentHashMap;
import java.util.function.Function;
import javax.net.ssl.ExtendedSSLSession;
import javax.net.ssl.SNIHostName;
import javax.net.ssl.SNIServerName;
import javax.net.ssl.SSLEngine;
import javax.net.ssl.SSLSession;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.StandardConstants;
import javax.net.ssl.X509ExtendedKeyManager;

/**
 * <b>The interception listener's key, picked per handshake by SNI</b> (qits-2644): the server name
 * the client asked for is looked up in {@link LeafCertificates#leafFor}, and that host's leaf — its
 * in-memory key and the chain qits-certificates signed — is what the handshake presents.
 *
 * <ul>
 *   <li><b>No SNI, or a host this replica holds no valid leaf for</b>: no alias, so the handshake
 *       fails ({@code handshake_failure}). There is no default certificate.
 *   <li><b>Fresh per handshake</b>: nothing is cached across handshakes beyond the alias in use, so
 *       a renewed leaf is served from the next handshake on. (Vert.x' own SNI support builds and
 *       caches one {@code SslContext} per server name, which would keep serving a renewed host's
 *       old leaf; the listener therefore leaves Vert.x' SNI off and lets the JDK hand this manager
 *       the requested name.)
 *   <li><b>The alias is {@code <host>#<serial>}</b> and the leaf it named is held until it expires,
 *       so a renewal landing between {@code chooseEngineServerAlias} and {@code getPrivateKey} can
 *       never pair one leaf's key with another's chain.
 * </ul>
 *
 * <p>Server side only: every client method answers null. Never logs, and never hands a key to
 * anything but the JDK's handshake.
 */
public final class SniKeyManager extends X509ExtendedKeyManager {

  private final Function<String, Optional<Leaf>> leaves;

  /** The leaves handed out by alias, until they expire. */
  private final Map<String, Leaf> chosen = new ConcurrentHashMap<>();

  /** Over {@link LeafCertificates#leafFor}. */
  public SniKeyManager(LeafCertificates leaves) {
    this(leaves::leafFor);
  }

  SniKeyManager(Function<String, Optional<Leaf>> leaves) {
    this.leaves = leaves;
  }

  /** The DNS name a handshake asked for (SNI), lower case, or null. */
  public static String requestedHost(SSLSession session) {
    if (!(session instanceof ExtendedSSLSession extended)) {
      return null;
    }
    List<SNIServerName> names;
    try {
      names = extended.getRequestedServerNames();
    } catch (UnsupportedOperationException notKnown) {
      return null;
    }
    for (SNIServerName name : names) {
      if (name.getType() == StandardConstants.SNI_HOST_NAME) {
        String host =
            name instanceof SNIHostName hostName
                ? hostName.getAsciiName()
                : new SNIHostName(name.getEncoded()).getAsciiName();
        return host.toLowerCase(Locale.ROOT);
      }
    }
    return null;
  }

  @Override
  public String chooseEngineServerAlias(String keyType, Principal[] issuers, SSLEngine engine) {
    return engine == null ? null : choose(keyType, engine.getHandshakeSession());
  }

  @Override
  public String chooseServerAlias(String keyType, Principal[] issuers, Socket socket) {
    return socket instanceof SSLSocket ssl ? choose(keyType, ssl.getHandshakeSession()) : null;
  }

  String choose(String keyType, SSLSession handshake) {
    String host = requestedHost(handshake);
    if (host == null) {
      return null;
    }
    Leaf leaf = leaves.apply(host).orElse(null);
    if (leaf == null || keyType == null || !keyType.equals(leaf.key().getAlgorithm())) {
      return null;
    }
    Instant now = Instant.now();
    chosen.values().removeIf(held -> !now.isBefore(held.notAfter()));
    String alias = host + "#" + leaf.serial();
    chosen.put(alias, leaf);
    return alias;
  }

  @Override
  public X509Certificate[] getCertificateChain(String alias) {
    Leaf leaf = alias == null ? null : chosen.get(alias);
    return leaf == null ? null : leaf.chain();
  }

  @Override
  public PrivateKey getPrivateKey(String alias) {
    Leaf leaf = alias == null ? null : chosen.get(alias);
    return leaf == null ? null : leaf.key();
  }

  @Override
  public String[] getServerAliases(String keyType, Principal[] issuers) {
    return null;
  }

  @Override
  public String[] getClientAliases(String keyType, Principal[] issuers) {
    return null;
  }

  @Override
  public String chooseClientAlias(String[] keyType, Principal[] issuers, Socket socket) {
    return null;
  }

  @Override
  public String chooseEngineClientAlias(String[] keyType, Principal[] issuers, SSLEngine engine) {
    return null;
  }

  /** Names nothing it holds. */
  @Override
  public String toString() {
    return "SniKeyManager";
  }
}
