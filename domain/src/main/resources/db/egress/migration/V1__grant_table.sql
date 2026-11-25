-- The grant table qits-deployments pushes (PUT /egress/api/grant-table, qits-2620): the one table
-- in force, kept here so both replicas read the same one. Each replica loads it at boot and re-reads
-- it when `version` moves.
--
--   id             the row's key; the store keeps one current table.
--   version        the table version qits-deployments computed; the read-back compares it.
--   body           the table as pushed: routes and refusals, verbatim.
--   received_at    when this replica stored it.
--   received_from  the pushing caller's principal (application:qits-deployments).
create table egress_grant_table (
    id            text        primary key,
    version       bigint      not null,
    body          jsonb       not null,
    received_at   timestamptz not null,
    received_from text        not null
);
