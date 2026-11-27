package eu.wohlben.qits.egress.identity;

import eu.wohlben.qits.auth.WorkloadPrincipal;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import javax.net.ssl.SSLPeerUnverifiedException;
import javax.net.ssl.SSLSession;

/**
 * <b>Who a TLS proxy connection's client certificate says is calling</b> (epic qits-2626,
 * qits-2759), for a request on 8082 that sends no bearer.
 *
 * <ul>
 *   <li>The chain was checked by the handshake: to the platform anchors only, EKU clientAuth (the
 *       listener's PKIX trust manager), so a certificate of another CA or an interception leaf never
 *       gets this far.
 *   <li>The principal is qits-auth-core's {@link WorkloadPrincipal#fromCertificate}: clientAuth,
 *       exactly one {@code urn:qits:principal:} URI of a known kind and a fit name, at most one
 *       project URI. The subject CN is never read. A certificate naming none is 401, reason {@code
 *       certificate-no-principal}.
 *   <li><b>Once per TLS session</b>: the answer is kept on the {@link SSLSession}, so every request
 *       of the connection (and a resumed session) is the same principal.
 * </ul>
 */
public final class ClientCertificates {

  static final String SESSION_KEY = "eu.wohlben.qits.egress.client-certificate";

  /** What a connection's certificate decided, and its serial (lower-case hex) when there is one. */
  public record Identified(CallerIdentity.Verdict verdict, String serial) {

    /** Whether the connection presented a certificate at all. */
    public boolean presented() {
      return serial != null;
    }
  }

  static final Identified NONE =
      new Identified(
          CallerIdentity.Verdict.refused(
              401, "no-credentials", "a bearer token or a client certificate is required"),
          null);

  private ClientCertificates() {}

  /** The session's verdict, read once and kept on the session. Never throws. */
  public static Identified of(SSLSession session) {
    if (session == null) {
      return NONE;
    }
    Object kept = session.getValue(SESSION_KEY);
    if (kept instanceof Identified identified) {
      return identified;
    }
    Identified fresh = read(session);
    try {
      session.putValue(SESSION_KEY, fresh);
    } catch (RuntimeException e) {
      // A session that keeps no values is read again next time; the answer is the same.
    }
    return fresh;
  }

  static Identified read(SSLSession session) {
    Certificate[] peer;
    try {
      peer = session.getPeerCertificates();
    } catch (SSLPeerUnverifiedException | RuntimeException e) {
      return NONE;
    }
    if (peer == null || peer.length == 0 || !(peer[0] instanceof X509Certificate leaf)) {
      return NONE;
    }
    return of(leaf);
  }

  /** The verdict about one client certificate whose chain the handshake already checked. */
  public static Identified of(X509Certificate leaf) {
    String serial = leaf.getSerialNumber().toString(16);
    WorkloadPrincipal principal = WorkloadPrincipal.fromCertificate(leaf);
    if (principal == null) {
      return new Identified(
          CallerIdentity.Verdict.refused(
              401,
              "certificate-no-principal",
              "the client certificate names no workload principal"),
          serial);
    }
    return new Identified(CallerIdentity.Verdict.of(Principal.of(principal)), serial);
  }
}
