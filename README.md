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
| 8081 | Vert.x server, the **proxy**: gateway form `/<route>/<rest>`, absolute-form `HTTPS_PROXY` requests and `CONNECT` (qits-2620, qits-2621, qits-2622) | `http://${QITS_ENVIRONMENT}-qits-egress:8081`, the wire alias on qits-net only; no edge routes it |

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

The door, the store and enforcement land in qits-2620; the deployer's push client is late work of
the epic, after qits-2620 is released.

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
