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
  `egress`). `V1__grant_table.sql` creates `egress_grant_table`; its entity, its store and the
  persistence unit (`quarkus.hibernate-orm.egress.*`) come with qits-2620. A new entity is marked
  for `CausationRowRules` (`CausedRow` or `@Uncaused`), and `EntityExposureTest` arrives with it.
- `service/` — the deployable: health and the management API under `/egress` on 8080, the proxy
  listener on 8081 (qits-2620), and every database-backed test.

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
- **Outbound calls** are guarded by `contracts/consumer/OutboundCallGuardTest`: each one is a row
  of that provider's consumer pact. The scaffold dials nothing itself; the proxy's upstream client
  and its idp calls (introspection, exchange) are named there with their rows when they arrive.
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
| `pacts/*_qits-idp-service.json` | `contracts/consumer/IdpPactTest` (the mint row run by `IdpTokenMintPactTest`) |

The first door brings `docs/openapi.yml` (`OpenApiSchemaExportTest`) and `golden-masters/**`
(`GoldenMasterRecordingTest`) in the same commit, and `release.yml` declares them then: the release
gate fails any operation of `docs/openapi.yml` that `golden-masters/index.json` does not cover. The
first entity brings `docs/entities.json` (`EntityExposureTest`) and `docs/database/egress.md`:

    ./mvnw -q -Dmaven.test.skip=true test-compile dependency:build-classpath \
      -Dmdep.outputFile=target/qits-classpath.txt -DincludeScope=runtime
    qits database diagram

## The userflow catalogue

`stories/**IT` boot the PACKAGED service (`-DskipITs=false`) against `idp.MockIdp` with the OIDC
tenant on, and write their reports under `service/target/userstories/`. The java-service release
recipe requires that directory and publishes it as `@userflows/qits-egress`.
