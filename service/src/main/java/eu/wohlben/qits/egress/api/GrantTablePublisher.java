package eu.wohlben.qits.egress.api;

import io.quarkus.security.identity.SecurityIdentity;
import jakarta.enterprise.context.ApplicationScoped;
import java.util.Set;
import org.eclipse.microprofile.config.inject.ConfigProperty;
import org.eclipse.microprofile.jwt.JsonWebToken;

/**
 * <b>Is this caller qits-deployments' own service client?</b> The grant-table door sits on a PUBLIC
 * host, and {@code qits:system} alone admits every platform service: any of them could otherwise
 * push a table granting itself any secret. So the push takes, beyond the role, exactly one caller:
 *
 * <ul>
 *   <li>a JWT (an identity with no token behind it never qualifies);
 *   <li>whose {@code sub} is {@code qits.egress.grant-table.publisher} — {@code
 *       ${QITS_ENVIRONMENT}-qits-deployments}, the deployer's idp client id. qits-idp writes a client
 *       token's client id into {@code sub} and sets no {@code azp}, and a granted claim is copied
 *       verbatim, so nothing else in the token is the client's to choose (qits-edge's route-table
 *       door learnt this in qits-2174);
 *   <li>whose {@code groups} hold {@code clients/<sub>} — the group qits-idp gives a client token
 *       of that very client, and no person's or agent's token;
 *   <li>and which holds {@code qits:system}.
 * </ul>
 *
 * <p>Anything else is a 403, written by the door.
 */
@ApplicationScoped
public class GrantTablePublisher {

  @ConfigProperty(name = "qits.egress.grant-table.publisher")
  String publisher;

  @ConfigProperty(name = "qits.egress.environment")
  String environment;

  /** Whether {@code identity} is the publisher. */
  public boolean is(SecurityIdentity identity) {
    return is(identity, publisher);
  }

  /** The rule, for a given publisher. Static and package-visible so it is asserted alone. */
  static boolean is(SecurityIdentity identity, String publisher) {
    if (identity == null || identity.isAnonymous()) {
      return false;
    }
    if (!(identity.getPrincipal() instanceof JsonWebToken jwt)) {
      return false;
    }
    String subject = jwt.getSubject();
    if (subject == null || !subject.equals(publisher)) {
      return false;
    }
    Set<String> groups = jwt.getGroups();
    return groups != null
        && groups.contains("clients/" + subject)
        && identity.hasRole(Roles.SYSTEM);
  }

  /** The publisher as a principal, the form {@code received_from} keeps. */
  public String principal() {
    String prefix = environment + "-";
    return publisher.startsWith(prefix) && publisher.length() > prefix.length()
        ? "application:" + publisher.substring(prefix.length())
        : "subject:" + publisher;
  }
}
