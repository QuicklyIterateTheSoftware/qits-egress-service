package eu.wohlben.qits.egress.tls;

import java.util.concurrent.CompletionStage;

/**
 * Issues one host's leaf: generates its key, has it certified, answers the {@link Leaf}. The
 * deployed one is {@link LeafDoor} (qits-certificates); a suite hands {@link LeafCertificates} its
 * own.
 */
@FunctionalInterface
public interface LeafIssuer {

  /** A new leaf for {@code host}, or a failed stage ({@link LeafIssueFailed} when refused). */
  CompletionStage<Leaf> issue(String host);
}
