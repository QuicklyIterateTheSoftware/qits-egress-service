# qits-egress-service

The platform's **egress gateway** (epic qits-2523). A platform application that calls a third party
(a DNS provider's API, a package host) does not hold that party's secret and does not dial it
directly: it calls qits-egress, which

1. identifies the caller from its bearer (a JWT verified offline against qits-idp's JWKS, or an
   opaque `qits_tok_…` introspected at qits-idp) and maps it to a principal
   (`application:<application>` for a platform service client);
2. admits the call only if the **grant table** gives that principal the route, and the method is one
   of the route's `methods` (403 `{"error":"no grant",…}` otherwise);
3. strips the caller's credentials and injects the route's secret (`QITS_EGRESS_SECRET_<NAME>`, a
   secret setting of this application) — or, for a platform route `platform:<label>`, the caller's
   bearer exchanged at qits-idp;
4. scrubs the secret out of the answer's headers and body;
5. writes one audit line per call on logger `eu.wohlben.qits.egress.audit`.

The design is on the epic's dossier (`egress-service-design`, `egress-service-tasks`), corrected by
the epic's thread comment of 2026-11-25 (the push model, below), which overrides the dossier where
they differ.

The application is `qits-egress`, image `qits/qits-egress`, two replicas.

## Two listeners

| Port | What | Reached by |
|---|---|---|
| 8080 | Quarkus HTTP, the **management** listener: `/egress/api` (the grant-table door) and `/egress/q` (health) | `https://egress.qits.<domain>/egress` through the **public** edge; the deployer's healthcheck at `/egress/q/health/ready` |
| 8081 | Vert.x server, the **proxy**: gateway form `/<route>/<rest>` (qits-2620); absolute-form `HTTPS_PROXY` requests and `CONNECT` come with qits-2622, streams and drain with qits-2621 | `http://${QITS_ENVIRONMENT}-qits-egress:8081`, the wire alias on qits-net only; no edge routes it |

## The grant table is pushed, not pulled

qits-deployments computes the grant table (every application's `.config/qits/egress.yml` routes and
the refusals) and serves it at `GET /deployments/api/egress-grants`. But qits-deployments is
`exposure: private`, and qits-egress is **public** (its first caller, qits-edge, is on qits-net, and
a service sits on exactly one network): a public service cannot reach a private one. Private →
public works — the deployer already pushes the edge's route table that way — so:

- qits-deployments **pushes** the table: `PUT /egress/api/grant-table`, admitted only for the
  deployer's own client (`sub` = `${QITS_ENVIRONMENT}-qits-deployments`, `qits:system`). It pushes
  when the table's version changes and, on each observation tick, reads `GET
  /egress/api/grant-table` back and pushes again when the version held differs.
- qits-egress **stores** the table in its own database (`egress_grant_table`, schema `egress`), so
  both replicas see the one the PUT stored. Each replica loads it at boot and re-reads it every 5 s
  when the version moves.
- Until a table exists, every proxied call answers **503 "no grant table yet"**. Readiness does
  **not** wait for it, or the first deployment could never pass its gate.

The deployer's push client is late work of the epic, after qits-2620 is released; until it pushes,
the gateway answers every call 503.

## The grant-table door (8080, `/egress/api`)

| Door | Who | Answers |
|---|---|---|
| `PUT /egress/api/grant-table` | qits-deployments' own client only: `@RolesAllowed("qits:system")` **and** a JWT whose `sub` is `qits.egress.grant-table.publisher` (`${QITS_ENVIRONMENT}-qits-deployments`) and whose `groups` hold `clients/<sub>` (`api/GrantTablePublisher`). Any other caller, another `qits:system` service included, is 403. | 204 stored, 204 when the same version is held (idempotent), 409 `{"error","held"}` when older, 400 without a version |
| `GET /egress/api/grant-table` | the same publisher, `qits:admin`, `qits:admin-agent`, `qits:desk-admin`, `qits:agent` | 200 `{version, receivedAt, routes, refused}`, 404 when none is held |

The body is exactly the deployer's table (`GET /deployments/api/egress-grants`): `{version,
routes:[{application, environment, deployedVersion, name, target, secret, inject, methods[]}],
refused:[{application, deployedVersion, reason}]}`. It is stored by plain JDBC in
`egress.egress_grant_table` (one row, the body as `jsonb`); the conditional upsert stores only a
higher version, so two replicas taking two pushes cannot store the older one last.

**Replica sync** (`grants/GrantIndex`): the replica that took the push adopts it at once; every
replica loads the table at boot and reads the held version every `qits.egress.grants.refresh` (5 s),
re-reading the body only when it moved. In memory the table is an immutable index `(application,
route name) → route`, compiled once (target, injection), replaced whole.

## The gateway (8081)

`/<route>/<rest>?<query>`, one call in this order (`proxy/EgressProxy`):

1. **Caller** from `Authorization: Bearer` (`identity/CallerIdentity`): a JWT is validated offline
   (RS256, a `kid` of the idp's JWKS, the issuer of the idp's discovery, `exp`, `aud` holding
   `qits-platform`); a `qits_tok_…` is introspected at `<idp>/api/tokens/introspect` with this
   service's own Basic client pair, cached 15 s against a SHA-256 of the token. Missing or bad →
   **401** JSON with `WWW-Authenticate: Bearer realm="qits-egress"`; idp unreachable → **503**.
2. **Principal**: `sub` = `${QITS_ENVIRONMENT}-<application>` with `groups` holding `clients/<sub>`
   and `qits:system` is `application:<application>`; else `agent:<agent>`, `project:<project>`,
   `subject:<sub>`. Only `application:` principals hold routes.
3. **No table held** → **503** `{"error":"no grant table yet"}`.
4. **Grant**: the route (caller application, `<route>`) must exist and its `methods` hold the
   method, else **403** `{"error":"no grant","principal","route","method"}`. A path with a `.`/`..`
   segment is 400.
5. `platform:` routes → **501** (qits-2623). A secret this process does not hold → **502**
   `{"error":"secret not configured"}`.
6. **Out** through `vertx-http-proxy` (bodies stream both ways) to `<target><rest>?<query>` over
   TLS, `Host` the target's. Removed: `Authorization`, `Proxy-Authorization`, `Cookie`, every
   `X-Qits-*` header and the hop-by-hop set. Injected: `inject: bearer` → `Authorization: Bearer
   <secret>`; `inject: header:<Name>` → `<Name>: <secret>`.

WebSocket upgrades are not spliced yet (qits-2621): the proxy's own upgrade path would skip the
interceptors, so it is off and an upgrade travels as a plain request.

### Secrets

A route's `secret: HETZNER_DNS` is the value of the environment variable
`QITS_EGRESS_SECRET_HETZNER_DNS` — a secret setting (`pd_setting`, `secret: true`) of the
application `qits-egress`. Read once at boot into `proxy/SecretStore`; the boot log names the secrets
held, never a value; no value reaches a log, an error body or an audit line.

### The audit line

One INFO line per call on logger `eu.wohlben.qits.egress.audit`, written when the response ends or
the connection closes:

    egress decision=ALLOW|DENY principal=<p> route=<r> method=<M> target=<host> path=<path without query> status=<n> durationMs=<n> reason=<reason or ->

`status` is the upstream's for an allowed call and the gateway's own otherwise. Reasons:
`no-credentials`, `bad-credentials`, `idp-unreachable`, `no-table`, `no-route`, `bad-path`,
`no-grant`, `method-not-granted`, `platform-route`, `bad-route`, `no-secret`, and on an ALLOW
`upstream-unreachable` when the proxy answered 502 itself. Never a header value, a query value, a
body or a secret; caller-influenced values are reduced to a safe alphabet.

## What it may call

qits-egress is public, so it reaches **public platform services only**: qits-idp (at
`https://idp.qits.<domain>/idp`), qits-observability's OTLP intake, and public targets of platform
routes. qits-projects, qits-deployments, qits-ci and every other private service are unreachable
from it — never add a call to one. A private caller or target needs a private egress variant, which
is follow-up work.

## Deployment

`.config/qits/deployments.yml`: `host: egress`, `routes: /egress`, `health_path:
/egress/q/health/ready`, `resources: postgresql:db:qits_egress, idp:client`, `replicas: 2`,
`stop_grace_period: 6m`, no `exposure:` (public). With `replicas:` there is no `publishes:` and no
stop-first.

Shutdown: `quarkus.shutdown.delay=10s` (swarm takes the task out of the VIP, readiness DOWN), then
the drain waits for in-flight requests and tunnels up to `quarkus.shutdown.timeout=5m`. Open
streams are not closed early: a restart must drop no running call. `stop_grace_period: 6m` is above
that sum.

## Build

`./mvnw verify` on a clone of this repository alone: no docker, no monorepo. The store is a real
postgres spawned by the suite (zonky). The packaged story (`stories/**IT`) runs with
`-DskipITs=false`. The native image is built by `docker/Dockerfile`.
