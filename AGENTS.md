# qits-egress — working notes

Read `README.md` first: it is the design. This file is the conventions on top of it. Grow it with
the code.

## The rule that shapes everything

**A clone of this repo alone builds and tests green** — no monorepo, no docker, no prior
`mvn install` elsewhere. `./mvnw verify` is the gate. The store is postgres and costs no docker:
`service/src/test/.../testdb/EmbeddedPg` spawns zonky's real binaries as a child process. **Never
Testcontainers, never a Quarkus dev service.**

The one address that is an exception is the platform Maven repository (`<repositories>` in the root
pom), where the qits-* jars live. Their versions are pinned in the root pom, exactly, and moved by
qits-maintenance's bumps — never by hand (a first adoption is the exception: it gets no bump).

## Layout

- `domain/` — owns the `egress` datasource and the Flyway lineage at `db/egress/migration` (schema
  `egress`). `V1__grant_table.sql` creates `egress_grant_table`; `store/GrantTableStore` reads and
  writes its one row by **plain JDBC** — no persistence unit, no entity. The first entity, if one
  ever comes, is marked for `CausationRowRules` (`CausedRow` or `@Uncaused`) and brings
  `EntityExposureTest`, `docs/entities.json` and `entities:`/`database:` in release.yml.
- `service/` — the deployable:
  - `api/` the grant-table door (`GrantTableResource`, the publisher check `GrantTablePublisher`,
    the wire records `GrantTableWire`, their native registration `ApiWireReflection`);
  - `grants/` the in-memory index each replica enforces and its refresh (`GrantIndex`, `GrantRoute`);
  - `identity/` the proxy listener's caller identity (`CallerIdentity`, `IdpKeys`, `SignedJwt`,
    `IdpIntrospection`, `Principal`), copied from qits-edge and adapted;
  - `proxy/` the 8081 listener (`EgressProxy`), what leaves for the upstream (`EgressOutbound`),
    the audit line (`AuditLine`), the secrets (`SecretStore`), the scrubbing (`Scrubber`,
    `ScrubbingReadStream`, `ResponseScrub`), the exchanges in flight and the drain (`InFlight`),
    and the qits-edge copies (`EdgeHopByHop`, `EdgeRequestFraming`, `UpstreamRetry`,
    `UpstreamKeepAlive`, `UpstreamChannel`, `ProxyClients`, `UpstreamPools`/`UpstreamLease`/
    `UpstreamOrigin`, `WebSocketSplice` from `EdgeWebSocketUpgrade`, `ShutdownLinger`). qits-edge's
    `DrainCount` has no copy: it repairs Quarkus' HTTP drain count, and the proxy listener is a
    plain Vert.x server that `InFlight` counts itself.

## Conventions

- **Two listeners, two audiences.** 8080 is behind the public edge (`host: egress`, `routes:
  /egress`): the grant-table door and health. 8081 is the proxy, reached only on the wire alias
  `${QITS_ENVIRONMENT}-qits-egress:8081`. Never put proxy traffic on 8080 or a management door on
  8081.
- **The grant table is pushed** by qits-deployments (`PUT /egress/api/grant-table`, its client
  only) and stored in the database; this service never pulls it. Readiness never waits for it.
- **Public, so public peers only.** No call to qits-projects, qits-deployments, qits-ci or any other
  `exposure: private` service: from qits-net it times out or hits the public edge, which refuses it
  (qits-agents paid for this in qits-2518).
- **Outbound calls** are guarded by `contracts/consumer/OutboundCallGuardTest`: only the classes in
  its `DIALLERS` reach an HTTP client, each named with the rows that cover its calls (the idp's
  discovery, JWKS and `introspectToken`). The proxy's upstream calls go to third parties and carry
  no pact; a `platform:` route's call (qits-2623) brings its row.
- **The proxy listener is not Quarkus HTTP.** Nothing on 8081 passes quarkus-oidc, the security
  layer or a JAX-RS filter: every check is in `proxy/EgressProxy`, and every refusal it writes is
  JSON and audited. A new request form (qits-2622) goes through the same `CallerIdentity` and the
  same audit line.
- **Never forward an upgrade through `HttpProxy`'s own WebSocket path**: it skips the interceptors,
  so the caller's credentials would leave and no secret would be injected. It is off
  (`setSupportWebSocket(false)`); `WebSocketSplice` handshakes with the headers
  `EgressProxy.handshakeHeaders` + `EgressOutbound.inject` prepare, the same as an ordinary call.
- **Every exchange is settled exactly once** (`InFlight.Exchange`), and the audit line is written
  from that settlement. A new way of answering (a splice, a tunnel) calls `Exchange.splice()` before
  `toNetSocket()` and `settle()` on the socket's close, or the drain waits out its 5 minutes.
- **A secret route's answer is scrubbed, streamed**: never buffer a body to scrub it. A new route
  kind that injects a secret adds `ResponseScrub` to its chain; one that injects none (a platform
  route) does not.
- **Suites that drain** call `EgressProxy.reopen()` afterwards (`EgressStreamingTest`); the
  listener is shared by every `@QuarkusTest` of the profile.
- **Secrets** (`QITS_EGRESS_SECRET_*`) never reach a log, a door, an error body or an audit line.

## Native traps

Green in `./mvnw verify`, broken only in the native binary. Keep them in mind:

- **`java.util.ServiceLoader`**: Quarkus switches GraalVM's service-loader feature off. The first
  code that loads a provider from `META-INF/services` adds
  `quarkus.native.auto-service-loader-registration=true` in the same commit (qits-agents
  2026.1123.194720 found no roster at all without it).
- **Reflection**: every type bound by Jackson on a door or an outbound client is registered for
  reflection (`@RegisterForReflection`), with a test that the list is complete.
- **No eventstream** here today; a service that adds one takes over the outbox datasource and the
  bearer rules of qits-eventstream.

## Generated files, and how to regenerate each

Every one of these compares by default and fails with a diff; `-Dgolden.update=true` rewrites.

| File | Written by |
|---|---|
| `pacts/*_qits-idp-service.json` | `contracts/consumer/IdpPactTest` (the mint row run by `IdpTokenMintPactTest`, the introspection rows by `IdpIntrospectionPactTest`) |
| `golden-masters/**` | `contracts/GoldenMasterRecordingTest`, states in `contracts/ProviderStates` |
| `docs/openapi.yml` | `api/OpenApiSchemaExportTest` (always rewrites; the diff is the review) |

The release gate fails any operation of `docs/openapi.yml` that `golden-masters/index.json` does not
cover, so a new door joins `GoldenMasterRecordingTest.INTERACTIONS` in the same commit. The
provider states are `a grant table is held` and `no grant table is held`; both grant
`Bearer contract-qits-deployments` as the deployer's own client and hand it as `authorization`.
`ConsumerPactVerificationTest` verifies pinned consumer pacts (none yet; qits-deployments' push
client is the first — then flip `ClasspathPactLoader.REQUIRED`).

## The suites' idp

Every `@QuarkusTest` points `qits.egress.idp.url` at `testdb/SuiteIdp` (registered by
`testdb/MockIdpConfigSource`): discovery and a settable token introspection, in front of
`MockIdp`'s issuer and JWKS, so tokens minted with `MockIdp.token()` validate at the gateway.
MockIdp's own stubs cannot be used from a `@QuarkusTest` (a different class loader started it);
`SuiteIdp` crosses loaders through system properties. The gateway suite's upstream is plain http,
allowed only by `qits.egress.test.allow-plain-http=true` in the test properties.

## The userflow catalogue

`stories/**IT` boot the PACKAGED service (`-DskipITs=false`) against `idp.MockIdp` with the OIDC
tenant on, and write their reports under `service/target/userstories/`. The java-service release
recipe requires that directory and publishes it as `@userflows/qits-egress`.
