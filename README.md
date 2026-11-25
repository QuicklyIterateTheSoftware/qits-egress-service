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
| 8081 | Vert.x server (HTTP/1.1, no h2c), the **proxy**: gateway form `/<route>/<rest>` (qits-2620), streams, WebSockets, scrubbing and the drain (qits-2621), absolute-form `HTTP(S)_PROXY` requests and `CONNECT` (qits-2622) | `http://${QITS_ENVIRONMENT}-qits-egress:8081`, the wire alias on qits-net only; no edge routes it |
| 8443 | Vert.x server, TLS, bound to **127.0.0.1 only**: the **interception** listener, where a granted `CONNECT`'s TLS ends (qits-2644) | only by the proxy's own tunnels; nothing outside the process' network namespace |

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

Three request forms, one path through identity, grant, injection, scrubbing and audit:

| Form | Request | Caller from | Route |
|---|---|---|---|
| gateway | `GET /<route>/<rest>?<query>` | `Authorization: Bearer` (401 + `WWW-Authenticate`) | by name |
| absolute | `GET https://host/path` or `GET http://host/path` sent to the proxy (`HTTP_PROXY`/`HTTPS_PROXY` clients) | `Proxy-Authorization` (407 + `Proxy-Authenticate: Basic realm="qits-egress"`) | by origin and base path |
| tunnel | `CONNECT host:port` (443 when left out) | `Proxy-Authorization` (407) | a route whose target is that host:port and whose `methods` hold `CONNECT` |

The gateway form, one call in this order (`proxy/EgressProxy`):

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
5. A secret this process does not hold → **502** `{"error":"secret not configured"}`. A
   `platform:` route takes the platform path instead (below).
6. **Out** through `vertx-http-proxy` (bodies stream both ways) to `<target><rest>?<query>` over
   TLS, `Host` the target's. Removed: `Authorization`, `Proxy-Authorization`, `Cookie`, every
   `X-Qits-*` header and the hop-by-hop set. Injected: `inject: bearer` → `Authorization: Bearer
   <secret>`; `inject: header:<Name>` → `<Name>: <secret>`. `Accept-Encoding: identity`, so the
   answer can be scrubbed.
7. **Back**, scrubbed (below), streamed as it arrives.

### Platform routes (`platform:<label>`)

A route `target: platform:<label>` reaches the platform service `<label>` at its public edge host,
`https://<label>.qits.${QITS_DOMAIN}` (`qits.egress.platform.origin`, `{label}` replaced;
`QITS_DOMAIN` is injected into every container). qits-egress is public, so only **public** platform
services can be reached this way (the epic's 2026-11-25 correction); a private one needs a private
egress variant.

- **The caller's bearer is exchanged** at qits-idp (RFC 8693, qits-2613;
  `identity/IdpTokenExchange`, `identity/PlatformBearers`): `POST <idp>/token`, the base the
  service's own oidc client mints at, with this service's Basic client pair
  (`QITS_RESOURCE_IDP_CLIENT_ID/_SECRET`, `${QITS_ENVIRONMENT}-qits-egress`, the actor idp allows by
  default), `grant_type=urn:ietf:params:oauth:grant-type:token-exchange`, `subject_token=<the
  caller's raw bearer, JWT or qits_tok_>`,
  `subject_token_type=urn:ietf:params:oauth:token-type:access_token`. idp answers a JWT whose
  `sub`, groups, project, agent… are the caller's and whose `act.sub` is
  `${QITS_ENVIRONMENT}-qits-egress`: the target sees who called, and that it came through the
  gateway; nothing is widened.
- **Cached** per SHA-256 of the caller's bearer until 30 s before the exchanged token expires (one
  with less life is not cached), bounded at 4096 entries; a refusal is not cached.
- **Sent** as `Authorization: Bearer <exchanged>` to the platform target and nowhere else:
  `proxy/PlatformOutbound` refuses a route that is not a platform route, and a third-party route's
  `EgressOutbound` removes every `Authorization` and writes its secret. The caller's own
  credentials, cookie and `X-Qits-*` are removed as for any route. No secret is injected and
  nothing is scrubbed.
- **Refused** by idp (`unauthorized_client`, `invalid_grant`, anything not 200): **502**
  `{"error":"token exchange refused"}`, audit DENY reason `exchange-refused`. idp unreachable:
  **503**, reason `idp-unreachable`.

Platform routes take every request form: the gateway form, absolute-form at the platform origin,
and WebSockets (spliced with the exchanged bearer on the handshake); never `CONNECT`.

### HTTPS_PROXY clients (absolute-form and CONNECT)

A client configured with `HTTPS_PROXY=http://<any user>:<bearer>@${QITS_ENVIRONMENT}-qits-egress:8081`
(or `HTTP_PROXY`) reaches the gateway without knowing its route names:

- **`Proxy-Authorization`** (`proxy/ProxyCredential`) is `Basic base64(<any user>:<bearer>)` — the
  user is ignored, the password is the bearer — or `Bearer <bearer>`. The bearer then goes through
  the same `CallerIdentity` (JWT offline, `qits_tok_` introspected). Missing, unreadable or refused:
  **407** with `Proxy-Authenticate: Basic realm="qits-egress"`, so a client that holds the
  credential sends it on the second try (the JDK does).
- **Absolute-form** (`proxy/AbsoluteTarget`): the caller's granted route whose target ORIGIN is the
  request's — scheme, host, port with each scheme's default — and whose base path prefixes the
  path on a segment boundary; of several, the longest base path. A platform route's origin is
  `https://<label>.qits.${QITS_DOMAIN}`. `http://host[:80]/…` also matches a route
  `https://host[:443]`: a client may send plain http on qits-net, and the gateway is the TLS client —
  nothing leaves in plain http that the route did not declare. (A client that tunnels its
  `https://` URLs with `CONNECT` gets the same treatment inside the tunnel, below.) Then the same method check,
  injection, scrubbing and audit as the gateway form, the upstream path being the request's own.
  No route: **403** `{"error":"no grant","principal","route","method","target"}`.
- **`CONNECT host:port`** (`proxy/ConnectTunnel`, `proxy/Interception`): only for an `https` route
  whose target is that host and port and whose `methods` hold `CONNECT`, never a platform route or
  a plain-http one. The tunnel's **TLS is ended here** (qits-2644, below): every request inside it
  is served like an absolute-form request. A route that reaches the host:port without `CONNECT`, or
  none at all: **403**. No leaf for the host: **503**.

### TLS interception in `CONNECT` tunnels (qits-2644)

A client behind `HTTPS_PROXY` tunnels every `https://` URL with `CONNECT`. The gateway does not
splice that tunnel to the target: it ends the client's TLS itself, with a leaf for the host certified
by the platform CA (qits-certificates, which every platform workload trusts), so the requests inside
are seen, granted, injected, scrubbed and audited like any other.

1. **The grant**, as above: an `https` route of the caller's for that host:port with `CONNECT`.
2. **The leaf** (`tls/LeafCertificates`): the one held, or one issued inline within
   `qits.egress.leaves.timeout` (10 s). None: **503** `{"error":"no certificate for the host yet"}`,
   audit `DENY reason=no-leaf`.
3. **`200 Connection Established`**, and the caller's socket spliced (back-pressure both ways) to a
   fresh connection to the **interception listener**, a second Vert.x server on
   `127.0.0.1:${qits.egress.tls.port}` (8443), bound to loopback only. The caller's principal, the
   granted route and the `host:port` are recorded under that loopback connection's LOCAL port —
   the remote port the listener sees — and removed when the splice closes. A loopback connection
   with no entry gets **403** (reason `no-tunnel`).
4. **The handshake**: TLS, ALPN `http/1.1` only, the JDK's `SSLEngine`. The key and chain are picked
   per handshake by SNI (`tls/SniKeyManager`, an `X509ExtendedKeyManager` reading the requested
   name from the handshake session and asking `LeafCertificates.leafFor`): no SNI, or a name this
   replica holds no valid leaf for, fails the handshake. Vert.x' own SNI switch is off — it caches a
   `SslContext` per name, which would keep serving a renewed host's old leaf.
5. **Each inner request** is an ordinary HTTP request on that listener: its caller is the tunnel's,
   its target origin `https://<SNI host>:<CONNECT port>`, and then the absolute-form path — the
   route matched by origin and base path, the `methods` check on the **inner** method (403),
   `Authorization`/`Proxy-Authorization`/`Cookie`/`X-Qits-*` removed, the route's secret injected,
   `Accept-Encoding: identity`, the answer scrubbed and streamed (SSE and WebSockets inside the
   tunnel take the same streaming paths). An SNI that is not the `CONNECT`'s host, or a `Host`
   header that is not the SNI host (or names another port): **421**, reason `misdirected`. A route
   whose secret this process does not hold answers what the absolute form answers: **502** `secret
   not configured`.
6. **Upstream TLS** is the proxy pools' own: verified against the JVM's default trust store
   (`quarkus.ssl.native=true`), never the platform anchors and never trust-all. Only the suites
   replace it, through the test-only `qits.egress.test.upstream-trust` (a PEM file).

An intercepted tunnel is one exchange in flight from its `CONNECT` until its sockets close, so the
drain waits for it (and the requests inside it are counted too).

### The TLS self-check (`tls/TlsSelfCheck`)

The live proof that a tunnel's TLS ends with a platform-issued leaf. `.config/qits/egress.yml`
declares the route `tls-self-check` → `https://api.hetzner.cloud`, `methods: [CONNECT, HEAD]`, for
qits-egress itself (principal `application:qits-egress`). When the table in force grants it and the
host's leaf is held (it waits up to 2 minutes for pre-issue), the egress

1. reads the platform anchors, `GET ${qits.egress.certificates-url}/api/anchors` with `Accept:
   application/json` (a public door; each anchor's `subject` and the `sha256` of its DER
   certificate, pacted as `one ACTIVE anchor`);
2. opens `CONNECT api.hetzner.cloud:443` on its own `127.0.0.1:8081` with `Proxy-Authorization:
   Bearer <its own qits client token>`;
3. handshakes inside the tunnel trusting **only** those anchors (`tls/AnchorTrust`: a certificate of
   the presented chain must BE a published anchor — its digest listed — and becomes the one trust
   anchor of a standard PKIX validation, host name included; the JVM's trust store plays no part);
4. sends `HEAD /v1/` (reads nothing).

One line on logger `eu.wohlben.qits.egress.tls`:

    egress tls self-check ok host=api.hetzner.cloud leafSerial=<hex> issuer=<anchor subject> status=<n>   (INFO)
    egress tls self-check failed host=<h> reason=<r> retryIn=<d>                                        (WARN)

`status` is the upstream's answer to the `HEAD`: while `QITS_EGRESS_SECRET_HETZNER_DNS` is not set
the inner request answers 502 `secret not configured`, and the check still proves the chain. A
failure retries after `qits.egress.leaves.backoff-min` (30 s) doubling to `backoff-max` (10 min). It
runs again when the route's target changes and when the anchors' `version` moves (read every
`qits.egress.tls.self-check.anchors-interval`, 10 min). It never touches readiness.

| Key | Default |
|---|---|
| `qits.egress.tls.port` | `8443` (`0` in `%test`) |
| `qits.egress.tls.self-check.enabled` | `true` (`false` in `%test`) |
| `qits.egress.tls.self-check.anchors-interval` | `10m` |
| `qits.egress.test.upstream-trust` | unset: the JVM's trust (suites only) |

### Streams and WebSockets

- **Two upstream pools** (`proxy/UpstreamPools`, from qits-edge): a long-lived stream — a WebSocket
  upgrade, or a GET/HEAD whose `Accept` names `text/event-stream` (`EgressProxy.isStream`) — goes
  through a client of its own, so streams to one third party never fill the pool its ordinary
  calls need. Each pool counts its connections per origin, leases each to the exchange it carries
  (`proxy/UpstreamLease`, no query, no credential) and WARNs once a minute for an origin under
  pressure, naming the five oldest leases.
- **Bodies stream both ways**: an SSE event or a chunk reaches the caller when the upstream sends
  it, not when the upstream ends (`EgressStreamingTest`).
- **A WebSocket** (`proxy/WebSocketSplice`, from qits-edge's `EdgeWebSocketUpgrade`) goes through
  the same identity, grant and injection as any call: the handshake leaves with the caller's
  credentials, cookie and `X-Qits-*` removed and the route's secret injected, from the stream pool;
  on the upstream's `101` the two sockets are spliced with back-pressure, and a close on either side
  closes the other. Its audit line is written when the socket closes: `method=GET status=101
  reason=websocket`. vertx-http-proxy's own upgrade path skips the interceptors and stays off.

### Scrubbing (secret routes)

The upstream may echo the credential — an error quoting the request, a redirect carrying it. The
calling application must not learn it, so `proxy/Scrubber` replaces the secret, its base64
(standard and URL alphabet) and its URL-encoded forms with `[redacted]`:

- in every **response header** value, `Location` included;
- in the **body**, streamed (`proxy/ScrubbingReadStream`): a byte is released as soon as no form
  can start at it, so at most `len(longest form) - 1` bytes are ever held back and a value split
  across chunks is still caught; `Content-Length` is removed and the answer leaves chunked;
- an answer with a `Content-Encoding` other than `identity` (the request asked for identity) cannot
  be read, so it is refused: **502** `{"error":"the upstream answered with a content encoding"}`,
  audit ALLOW with reason `upstream-encoded`;
- the gateway's own error bodies are fixed texts, and the proxy's own 502 has no body.

Not scrubbed: WebSocket frames (spliced as bytes; a replacement would break a frame's length).

### Secrets

A route's `secret: HETZNER_DNS` is the value of the environment variable
`QITS_EGRESS_SECRET_HETZNER_DNS` — a secret setting (`pd_setting`, `secret: true`) of the
application `qits-egress`. Read once at boot into `proxy/SecretStore`; the boot log names the secrets
held, never a value; no value reaches a log, an error body or an audit line.

### The audit line

One INFO line per call on logger `eu.wohlben.qits.egress.audit`, written when the response ends or
the connection closes:

    egress decision=ALLOW|DENY principal=<p> route=<r> method=<M> target=<host> path=<path without query> status=<n> durationMs=<n> reason=<reason or ->

A request inside an intercepted tunnel appends ` tls=intercepted`; the `CONNECT` itself has
`target=<host:port>` and appends ` tls=intercepted leafSerial=<hex>` (the leaf the tunnel's handshake
is served), written when the tunnel closes.

`status` is the upstream's for an allowed call and the gateway's own otherwise. Reasons:
`no-credentials`, `bad-credentials`, `idp-unreachable`, `no-table`, `no-route`, `bad-path`,
`no-grant`, `method-not-granted`, `bad-route`, `no-secret`, `exchange-refused`, `bad-target` (an
absolute-form or `CONNECT` target that does not parse), `no-leaf` (a `CONNECT` whose host gets no
leaf), `misdirected` (an inner request whose SNI or `Host` is not the tunnel's, 421), `no-tunnel` (a
loopback connection no tunnel opened), and on an ALLOW
`upstream-unreachable` when the proxy answered 502 itself, `upstream-encoded` when a secret route's
answer was encoded and refused, `websocket` for a spliced socket (written at its close, status 101). Never a header value, a query value, a
body or a secret; caller-influenced values are reduced to a safe alphabet.

## Per-host leaves (`tls/`, qits-2643)

Groundwork for TLS interception inside `CONNECT` tunnels (epic qits-2524, dossier "Egress TLS
interception"): every replica holds one **leaf certificate per `https://` target host** of the grant
table in force, certified by qits-certificates.

- **The key** is EC P-256, generated in this process per issuance (a renewal is a new key), and held
  in memory only: never written, never logged, never in a door's answer. `Leaf.toString()` carries no
  key.
- **The request** is a PKCS#10 CSR (subject `CN=<host>`, extensionRequest SAN `dNSName:<host>`),
  `POST ${qits.egress.certificates-url}/api/leaves` with `{"csr": "<PEM>"}` and the `qits` client's
  bearer (`tls/LeafBearer`; client id `<env>-qits-egress`, the requester qits-certificates admits).
  201 `{certificate, chain, serial, notAfter, anchorId}`; the chain's first certificate must certify
  the key held and name the host, or the answer is refused.
- **Pre-issue**: every adopted grant table (`grants/GrantTableAdopted`, fired by `GrantIndex` on a
  push taken here, a refresh that read a moved version, and the load at boot) hands its https hosts
  to `LeafCertificates.want`; each host without a valid leaf is issued asynchronously, at most
  `qits.egress.leaves.concurrency` (4) at a time. Platform routes and unusable routes are skipped.
- **Renewal** at `qits.egress.leaves.renew-fraction` (two thirds) of a leaf's life, checked every
  `qits.egress.leaves.check-interval` (5 s, in memory). A failure retries after a backoff doubling
  from `qits.egress.leaves.backoff-min` (30 s) to `qits.egress.leaves.backoff-max` (10 min); the old
  leaf is served until its notAfter. A host that left the table is not renewed and its leaf lapses.
- **On demand**: `LeafCertificates.issueNow(host)` answers the held leaf, joins the issuance in
  flight, or starts one outside the queue, failing after `qits.egress.leaves.timeout` (10 s) — for
  the `CONNECT` with no leaf. `leafFor(host)` gives the valid leaf (`key()`, `chain()`) the
  interception listener's `SniKeyManager` picks by SNI (qits-2644).
- **Readiness is not tied to leaves.** Nothing is shared between replicas. Without a `qits` client
  (a clone, the suites) nothing is asked for and each attempt is one WARN.

Log lines on logger `eu.wohlben.qits.egress.tls`:

    egress leaf issued host=<h> serial=<hex> notAfter=<iso>                                    (INFO)
    egress leaf failed host=<h> status=<n or -> reason=<r> retryIn=<d> serving=<serial or ->   (WARN)

| Key | Default |
|---|---|
| `qits.egress.certificates-url` | `https://certificates.qits.${QITS_DOMAIN}/certificates` (through the edge) |
| `qits.egress.leaves.renew-fraction` | `0.6667` |
| `qits.egress.leaves.concurrency` | `4` |
| `qits.egress.leaves.backoff-min` / `backoff-max` | `30s` / `10m` |
| `qits.egress.leaves.timeout` | `10s` (each call, and the inline wait) |
| `qits.egress.leaves.check-interval` | `5s` |

## What it may call

qits-egress is public, so it reaches **public platform services only**: qits-idp (at
`https://idp.qits.<domain>/idp`: JWKS, discovery, introspection and the token exchange, each with a
pact row in `pacts/qits-egress-service_qits-idp-service.json`), qits-certificates' leaf and anchors
doors (at `https://certificates.qits.<domain>/certificates`, through the edge), qits-observability's
OTLP intake,
and public targets of platform routes. qits-projects, qits-deployments, qits-ci and every other private service are unreachable
from it — never add a call to one. A private caller or target needs a private egress variant, which
is follow-up work.

## Deployment

`.config/qits/deployments.yml`: `host: egress`, `routes: /egress`, `health_path:
/egress/q/health/ready`, `resources: postgresql:db:qits_egress, idp:client`, `replicas: 2`,
`stop_grace_period: 6m`, no `exposure:` (public). With `replicas:` there is no `publishes:` and no
stop-first.

Shutdown, on SIGTERM:

1. `quarkus.shutdown.delay=10s`: swarm takes the task out of the VIP, readiness answers DOWN, and
   the proxy listener keeps serving (`ShutdownDelayInitiatedEvent` only logs what it carries).
2. The **drain** (`EgressProxy.draining` on `ShutdownEvent`, `proxy/InFlight`): a new connection to
   8081 is closed on arrival; every call in flight — and any request arriving on a connection
   already open — is served to its end, streams, WebSockets and tunnels included, up to
   `quarkus.shutdown.timeout=5m`. Nothing is closed early: a restart must drop no running call. The
   listener counts its own exchanges (Quarkus' HTTP drain does not see a plain Vert.x server): one
   is over when its response ends or closes, when its connection closes (a reset response), or — a
   spliced socket — when the socket closes. After the drain, a request on a connection still open
   has the connection closed unanswered, so its client retries elsewhere.
3. The **linger**, `qits.egress.shutdown.linger=10s` (`proxy/ShutdownLinger`, from qits-edge), so the
   kernel can send what the last answers handed it before swarm tears the namespace down.

`stop_grace_period: 6m` is above that sum.

## Build

`./mvnw verify` on a clone of this repository alone: no docker, no monorepo. The store is a real
postgres spawned by the suite (zonky). The packaged story (`stories/**IT`) runs with
`-DskipITs=false`. The native image is built by `docker/Dockerfile`.
