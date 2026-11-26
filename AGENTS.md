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
    `IdpIntrospection`, `Principal`), copied from qits-edge and adapted, and a platform route's
    token exchange (`IdpTokenExchange`, the cache `PlatformBearers`);
  - `proxy/` the 8081 listener (`EgressProxy`), what leaves for the upstream (`EgressOutbound`),
    the audit line (`AuditLine`), the secrets (`SecretStore`), the HTTPS_PROXY forms
    (`ProxyCredential`, `AbsoluteTarget`, `ConnectTunnel`), the scrubbing (`Scrubber`,
    `ScrubbingReadStream`, `ResponseScrub`), the exchanges in flight and the drain (`InFlight`),
    and the qits-edge copies (`EdgeHopByHop`, `EdgeRequestFraming`, `UpstreamRetry`,
    `UpstreamKeepAlive`, `UpstreamChannel`, `ProxyClients`, `UpstreamPools`/`UpstreamLease`/
    `UpstreamOrigin`, `WebSocketSplice` from `EdgeWebSocketUpgrade`, `ShutdownLinger`), and the
    interception of `CONNECT` tunnels (`Interception`: the loopback listener's options and the
    tunnels by loopback port; qits-2644), the forward (`ForwardDoor`, the `GET /egress/api/forward`
    websocket on 8080; `ForwardedCallers`, its callers by loopback port; qits-2654) and the
    passthrough (`Passthrough`, its rules and resolve-once check; `PassthroughNetwork`, the resolver
    and dial seam; `PassthroughOutbound`, what leaves for a plain-http target; the blind splice in
    `ConnectTunnel.blind`). qits-edge's
    `DrainCount` has no copy: it repairs Quarkus' HTTP drain count, and the proxy listener is a
    plain Vert.x server that `InFlight` counts itself.
  - `tls/` the per-host leaves (qits-2643): `LeafCertificates` (pre-issue, renewal, backoff,
    `issueNow`, `leafFor`), `LeafDoor` (the dial at qits-certificates and the `LeafIssuer` on it),
    `LeafKeys` (key, CSR, chain check), `LeafBearer` (the `qits` client's token), `LeafWiring` (the
    `GrantTableAdopted` observer, the periodic tick, the producer; a `LeafIssuer` bean replaces the
    door — the suites' `SuiteLeafIssuer`); and for interception (qits-2644) `SniKeyManager` (the key
    per handshake by SNI), `TlsSelfCheck` (the live proof, its schedule in `TlsSelfCheck.Runner`) and
    `AnchorTrust` (trust in the published anchors only).

## Conventions

- **Two listeners, two audiences.** 8080 is behind the public edge (`host: egress`, `routes:
  /egress`): the grant-table door and health. 8081 is the proxy, reached only on the wire alias
  `${QITS_ENVIRONMENT}-qits-egress:8081`. Never put proxy traffic on 8080 or a management door on
  8081. The one bridge is `GET /egress/api/forward` (`proxy/ForwardDoor`): a byte splice from an
  edge websocket to 8081 on `127.0.0.1`, deciding nothing itself but who opened it — every request
  over it is judged on 8081 like any other. Never serve or decide a proxied request on 8080. The third, the interception listener (`qits.egress.tls.port`, 8443), is bound to
  `127.0.0.1` and reached only by the proxy's own tunnels: never bind it anywhere else, and never
  serve a request on it whose tunnel entry is missing.
- **A tunnel's TLS ends here, and its requests take the absolute-form path** (`EgressProxy.absolute`):
  never add a second route match, injection or scrub for intercepted requests. A `CONNECT` reaches
  `https` routes only; a plain-http route is never tunnelled.
- **Upstream TLS is the JVM's public trust**, never the platform anchors and never trust-all. Only
  the suites replace it, with `qits.egress.test.upstream-trust` (`testdb/SuiteTlsConfigSource`).
- **The interception key is picked per handshake** (`tls/SniKeyManager`). Do not switch Vert.x' own
  SNI on for that listener: it caches one `SslContext` per name and a renewed leaf would never be
  served.
- **The grant table is pushed** by qits-deployments (`PUT /egress/api/grant-table`, its client
  only) and stored in the database; this service never pulls it. Readiness never waits for it.
- **Public, so public peers only.** No call to qits-projects, qits-deployments, qits-ci or any other
  `exposure: private` service: from qits-net it times out or hits the public edge, which refuses it
  (qits-agents paid for this in qits-2518).
- **Outbound calls** are guarded by `contracts/consumer/OutboundCallGuardTest`: only the classes in
  its `DIALLERS` reach an HTTP client, each named with the rows that cover its calls (the idp's
  discovery, JWKS, `introspectToken` and the exchange's `issueToken`). The proxy's upstream calls
  carry no pact: to a third party, or a platform route's call, which is the caller's own request
  passed through to a public platform service.
- **An exchanged bearer goes to a platform target only** (`PlatformOutbound` throws for any other
  route). Never put it in a header a third-party route forwards, never cache it under the token
  itself (`CallerIdentity.fingerprint`), never log it.
- **The proxy listener is not Quarkus HTTP.** Nothing on 8081 passes quarkus-oidc, the security
  layer or a JAX-RS filter: every check is in `proxy/EgressProxy`, and every refusal it writes is
  JSON and audited. Every request form (`EgressProxy.Form`: gateway, absolute, CONNECT) goes
  through the same `CallerIdentity` and the same audit line; the proxy forms answer 407, never
  401, for a missing or bad credential.
- **A forward's caller is looked up by loopback port only** (`ForwardedCallers.of`): the remote
  address must be loopback, since 8081 listens on every interface. A request's own
  `Proxy-Authorization` (gateway form: `Authorization`) always wins over the forward's caller; only
  a request with none is the forward's.
- **The passthrough is for principals with a project, never an application**
  (`Passthrough.applies`), and comes after every granted route. Resolve once, check EVERY address,
  dial the checked one (`Passthrough.Checked.dial`) — never hand the name to a client that would
  resolve it again. The caller's `Authorization` and `Cookie` go out on a plain-http passthrough
  (they are the caller's); never run `EgressOutbound`'s strip or an injection there, and never
  intercept a passthrough `CONNECT`. A new refusal is `403 {"error":"passthrough refused",
  "reason"}` with audit reason `passthrough-<reason>`.
- **The suites' names** (`proxy/SuitePassthroughNetwork`, a `PassthroughNetwork` bean): made-up
  `*.passthrough.test` names resolve to the literals a test lists, and a checked "public" address
  (`203.0.113.7`) is dialled on loopback, where the fake upstreams are. Never loosen the address
  check for a test instead.
- **Routes are held by principal** (`GrantIndex.Table`, keyed by `GrantTableWire.Route.principal`,
  which falls back to `application:<application>` for a table older than qits-2659). Every lookup
  goes through `Table.route(Principal, name)` / `Table.routes(Principal)`, which ask
  `Table.holders`: the caller's own principal, then an agent's `project:<its project>`. Never look a
  route up by the application name or by a hand-built key, and never give an `application:` caller
  a project's routes.
- **A secret route drops `Set-Cookie`** (`ResponseScrub`; `WebSocketSplice` when it scrubs): a new
  secret-injecting path drops it too. A platform route and the passthrough never do — that session
  is the caller's. `inject: cookie:<name>` writes the whole `Cookie` header, after
  `EgressOutbound.strip` removed the caller's.
- **A route matched by origin is matched exactly** (`AbsoluteTarget.match`): scheme, host and port,
  with the single `http:80 → https:443` allowance. Never widen it to "any port" or a host suffix: a
  caller could then reach what no route declares.
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
- **Leaf keys** never leave the process: no file, no log, no door, no `toString`. A new key per
  issuance. Readiness never waits for a leaf.
- **A change of the table in force** is announced as `grants/GrantTableAdopted` (a synchronous CDI
  event under `GrantIndex`'s lock): an observer records and schedules, never blocks or throws.

## Native traps

Green in `./mvnw verify`, broken only in the native binary. Keep them in mind:

- **`java.util.ServiceLoader`**: Quarkus switches GraalVM's service-loader feature off. The first
  code that loads a provider from `META-INF/services` adds
  `quarkus.native.auto-service-loader-registration=true` in the same commit (qits-agents
  2026.1123.194720 found no roster at all without it).
- **Reflection**: every type bound by Jackson on a door or an outbound client is registered for
  reflection (`@RegisterForReflection`), with a test that the list is complete.
- **Randomness**: never a `SecureRandom`, `KeyPairGenerator` or anything seeded in a static field
  or at build time — the image heap refuses it (qits-certificates' first native release). `tls/LeafKeys`
  creates each per call.
- **The interception listener** is the JDK's `SSLEngine` (`JdkSSLEngineOptions`), its key manager
  plain Java (`KeyCertOptions.wrap(X509KeyManager)`): no OpenSSL, no reflection, no Bouncy Castle
  provider. The self-check builds its `SSLContext`, `KeyStore` and PKIX `TrustManagerFactory` per
  run and passes no `SecureRandom` of its own. `quarkus.ssl.native=true` carries the JDK's TLS.
- **No JSON binding in `tls/`**: the leaf answer is read as a Vert.x `JsonObject` tree, so there is
  no type to register for reflection; a record bound by Jackson would join a `@RegisterForReflection`
  list with its test.
- **No eventstream** here today; a service that adds one takes over the outbox datasource and the
  bearer rules of qits-eventstream.

## Generated files, and how to regenerate each

Every one of these compares by default and fails with a diff; `-Dgolden.update=true` rewrites.

| File | Written by |
|---|---|
| `pacts/*_qits-certificates-service.json` | `contracts/consumer/CertificatesPactTest` (`leaf issued`, through the real `LeafDoor.post` with the state's CSR; `one ACTIVE anchor`, through `TlsSelfCheck.anchors` with `Accept: application/json`) |
| `pacts/*_qits-idp-service.json` | `contracts/consumer/IdpPactTest` (the mint row run by `IdpTokenMintPactTest`, the introspection rows by `IdpIntrospectionPactTest`, the exchange rows by `IdpTokenExchangePactTest`). Written by `IdpPactTest.theCommittedPactIsWhatTheRowsWrite`, not the library's `compareOrWritePactFile`: the exchange rows' form body gets a provider-state generator `$.subject_token = ${subjectToken}` the library cannot express (idp's states mint a fresh subject token) |
| `golden-masters/**` | `contracts/GoldenMasterRecordingTest`, states in `contracts/ProviderStates` |
| `golden-masters/**` of qits-deployments (read, not written) | `contracts/consumer/DeploymentsGrantTableTest` binds and indexes the deployer's `getEgressGrants` recordings (`an egress grant table with a project route`, `… with one route`, `an empty …`): the table it pushes here. Not a pact, since this service never calls qits-deployments; the pin `qits.deployments-golden-masters.version` moves with maintenance's bumps |
| `docs/openapi.yml` | `api/OpenApiSchemaExportTest` (always rewrites; the diff is the review) |

The release gate fails any operation of `docs/openapi.yml` that `golden-masters/index.json` does not
cover, so a new door joins `GoldenMasterRecordingTest.INTERACTIONS` in the same commit. The
provider states are `a grant table is held` and `no grant table is held`; both grant
`Bearer contract-qits-deployments` as the deployer's own client and hand it as `authorization`.
`ConsumerPactVerificationTest` verifies pinned consumer pacts (none yet; qits-deployments' push
client is the first — then flip `ClasspathPactLoader.REQUIRED`).

## The suites' idp

Every `@QuarkusTest` points `qits.egress.idp.url` at `testdb/SuiteIdp` (registered by
`testdb/MockIdpConfigSource`): discovery, a settable token introspection and a token exchange that
mints like qits-idp (`sub`/groups copied, `act.sub` the asking client; `refuseExchanges`,
`exchangeLife` set it), in front of `MockIdp`'s issuer and JWKS, so tokens minted with
`MockIdp.token()` validate at the gateway. The same config source points
`qits.egress.platform.origin` at SuiteIdp's `/platform/{label}`, the suites' platform service, which
records what it received. SuiteIdp parses JSON with Jackson, never Vert.x' `JsonObject`: in its
class loader Vert.x' JSON factory is Quarkus' and fails to load.
MockIdp's own stubs cannot be used from a `@QuarkusTest` (a different class loader started it);
`SuiteIdp` crosses loaders through system properties. The gateway suite's upstream is plain http,
allowed only by `qits.egress.test.allow-plain-http=true` in the test properties.

## The suites' TLS

`support/SuiteTls` makes two throwaway CAs, written once per JVM to a directory parked in a system
property so every class loader sees the same ones: `leaf` (signs the egress' leaf CSRs; the tunnel's
client trusts it) and `upstream` (signs the fake third party's `localhost` certificate; the upstream
pools trust it through `qits.egress.test.upstream-trust`, set by `testdb/SuiteTlsConfigSource`). In
every `@QuarkusTest` the leaves come from `tls/SuiteLeafIssuer` (a `LeafIssuer` bean; a host in
`REFUSED` is answered 503); the packaged `stories/egress/EgressInterceptionIT` goes through the real
`LeafDoor` to a fake qits-certificates in its own JVM and drives `curl -x` through a tunnel. The
self-check is off in `%test`: its schedule is `TlsSelfCheckTest`, its probe runs against the real
listeners in `EgressInterceptionTest`.

## The userflow catalogue

`stories/**IT` boot the PACKAGED service (`-DskipITs=false`) against `idp.MockIdp` with the OIDC
tenant on, and write their reports under `service/target/userstories/`. The java-service release
recipe requires that directory and publishes it as `@userflows/qits-egress`.
