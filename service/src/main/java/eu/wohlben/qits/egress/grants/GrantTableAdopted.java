package eu.wohlben.qits.egress.grants;

/**
 * A CDI event: this replica now enforces {@code table} — fired by {@link GrantIndex} whenever the
 * table in memory is replaced by a non-null one, whether a push landed here ({@link
 * GrantIndex#adopt}) or a refresh read a moved version (at boot, and on the replica that did not
 * take the push).
 *
 * <p>Observed synchronously, inside the index's lock: an observer only records and schedules, never
 * blocks and never throws (the tls leaves pre-issue for the table's https hosts on it, qits-2643).
 */
public record GrantTableAdopted(GrantIndex.Table table) {}
