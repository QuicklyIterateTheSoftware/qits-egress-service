-- The Claude subscription login qits-egress holds for every project's agents (epic qits-2525,
-- qits-2664): the runner hands it over (PUT /egress/api/claude-credential?mode=adopt) or a fresh
-- sign-in replaces it (mode=replace); the agents' containers keep only a placeholder, which the
-- proxy swaps for the access token held here. One row, id = 1; whichever replica takes the
-- refresh lock (SELECT ... FOR UPDATE) refreshes it, the other re-reads it.
--
-- PLAINTEXT, in this component's own database (encryption at rest is out of scope, see the epic's
-- thread). No door, log line or error body ever carries access_token or refresh_token.
--
--   access_token        the held OAuth access token, swapped in for the placeholder
--   refresh_token       the held refresh token; it rotates on every refresh
--   expires_at          when access_token expires; refreshed when less than the margin is left
--   refresh_expires_at  when refresh_token expires, when the login said so
--   scopes              space separated
--   subscription_type   e.g. max
--   rate_limit_tier     copied from the login
--   source              how it arrived: "hand-over <runner>" or "sign-in <runner>"
--   updated_at          when the row last changed (a store or a refresh)
--   last_refresh_at     the last successful refresh
--   last_refresh_error  why the last refresh failed; cleared by the next success or a new login
create table egress_claude_credential (
    id                 smallint    primary key check (id = 1),
    access_token       text        not null,
    refresh_token      text        not null,
    expires_at         timestamptz not null,
    refresh_expires_at timestamptz,
    scopes             text        not null,
    subscription_type  text,
    rate_limit_tier    text,
    source             text        not null,
    updated_at         timestamptz not null,
    last_refresh_at    timestamptz,
    last_refresh_error text
);
