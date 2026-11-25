package eu.wohlben.qits.egress.tls;

/**
 * qits-certificates did not give a usable leaf: the status it answered (0 when no answer was asked
 * for or read) and a reason safe to log — never a body, a token or key material.
 */
public final class LeafIssueFailed extends RuntimeException {

  private final int status;

  public LeafIssueFailed(int status, String reason) {
    super(reason, null, false, false);
    this.status = status;
  }

  /** The certificates door's status, 0 when there was none. */
  public int status() {
    return status;
  }
}
