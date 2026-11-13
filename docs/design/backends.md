# Backends

BrowserX keeps its state in SQLite files and a snapshot directory by default, and that stays the right choice for one worker. This page explains which other backends BrowserX can use, why each family is in or out, how several BrowserX workers (and other tools) can share one set of service instances, and what is guaranteed when a backend fails.

A family of backend is supported only where BrowserX has data of that kind. There are no stub integrations and no configuration keys that are read and ignored: a setting that BrowserX cannot honour is refused when the configuration loads.

## Support matrix

| Family | Engines | BrowserX use | Where configured | Status |
| --- | --- | --- | --- | --- |
| Relational | SQLite (default), PostgreSQL, MariaDB | The lease registry: one row per session, compare-and-swap on the fencing generation | worker `[database]` | Supported |
| Object store | S3 API: profiles `standard`, `edge`, `self-hosted`, `compatible` | Sealed snapshots (already encrypted bytes) | worker `[object_store]` | Supported |
| Cache / coordination | Valkey, Redis | Tool-call rate limits and engagement call budgets shared by several MCP servers | MCP `[cache]` | Supported |
| Analytics | ClickHouse | Append-only export of the MCP audit log for queries and retention | MCP `[analytics]` | Supported |
| Event stream | Kafka, RabbitMQ (AMQP 0-9-1) | Outbound export of the MCP audit log to a stream or an exchange | MCP `[events]` | Supported |
| Search | OpenSearch, Elasticsearch | Full-text and structured search over the MCP audit log | MCP `[search]` | Supported |

### Why each family is in

- **Relational.** The lease registry is relational data with a hard consistency rule: a lease changes only if its generation is the one the writer saw. SQLite does this for one worker. PostgreSQL and MariaDB move that state off the worker's disk, so a worker that is replaced (a rescheduled container, a new host with the same identity) finds its leases and recovers them, and the operator can back up, replicate and inspect the state with the database's own tools. They do **not** make two live workers share sessions: see [what sharing means](#what-sharing-means).
- **Object store.** A snapshot is one sealed blob per version, written once and read rarely: exactly what an object store is for. With a bucket, snapshots survive the loss of a worker's disk and a replacement worker can restore a persistent identity. Snapshots are encrypted with the snapshot key before they leave the process, so the store never sees plaintext and needs no trust. Profile directories (`persistence = "profile"`) are live browser directories bound to one worker and stay on local disk.
- **Cache / coordination.** Rate limits and call budgets of the MCP server are counters with a short life. One MCP server keeps them in memory. Several MCP servers in front of one worker need one shared counter, or the limit is multiplied by the number of servers. Valkey and Redis speak the same protocol, so both are supported.
- **Analytics.** The MCP audit log is a high-volume, append-only record of what agents did. The hash-chained file stays authoritative; ClickHouse receives a copy that operators can query by engagement, tool, reason code or time.
- **Event stream.** Security teams often want audit records in a stream they already run. Kafka and RabbitMQ are both supported because deployments use one or the other.
- **Search.** Incident work is text search over audit entries (a URL, a refusal reason, an engagement id). OpenSearch and Elasticsearch serve that with one shared REST and bulk API subset. It overlaps with ClickHouse for stored data, not for use: ClickHouse answers aggregate questions, a search engine answers "find the entries that mention this". An operator enables the ones they want.

### Why nothing else is in

- **Leases in Valkey/Redis.** A lease needs durable compare-and-swap with the other session state. A cache with expiry is the wrong home, and the relational store already gives it with one dependency.
- **Work queues (Kafka, RabbitMQ).** BrowserX has no work queue between nodes: admission queues are in-process, and sessions are bound to the worker that holds their browser. Streams are used only for export.
- **Object store for profiles, downloads, screenshots, traces.** Profile directories are live and local. Downloads and screenshots are handed to the client and not retained. BrowserX records no traces yet; when it does, they use this family.
- **Session or lease search.** Leases are listed and filtered by the relational store (owner, status). A search engine would hold a second copy with weaker consistency and no use.
- **Relational store for the audit log.** The audit log is an append-only hash chain in a local file, by design (an attacker with write access to a database could rewrite rows; the file is created `0600` and can be made append-only). Exports are copies.

## What sharing means

Several products, and several BrowserX workers, can use **one set of service instances**. Each product writes only inside its own namespace, and each worker only inside its own node scope.

| Service | Namespace of one product | Default | Rule |
| --- | --- | --- | --- |
| PostgreSQL | schema | `browserx` | tables and the migration table live in the schema; the schema is created if missing |
| MariaDB | database | `browserx` | one database per product; created if missing |
| SQLite | file | `<state_dir>/browserx.db` | one file per product |
| Valkey / Redis | key prefix, optional database index, ACL user | `browserx:` | only `SCAN` with the prefix; never `FLUSHALL`, `FLUSHDB` or `KEYS *` |
| Object store | bucket and key prefix | `browserx/` | one bucket can be shared; a worker never lists or deletes outside its prefix |
| ClickHouse | database | `browserx` | tables are created by versioned migrations |
| Kafka | topic prefix, consumer group prefix | `browserx.` | topics are not created or deleted by BrowserX |
| RabbitMQ | virtual host, exchange and queue prefix | `browserx.` | publisher confirms, bounded buffers |
| OpenSearch / Elasticsearch | index prefix | `browserx-` | an index outside the prefix is never read, written or deleted |

Migrations are per engine and versioned; every product owns its migration table inside its own namespace, and a database written by a newer schema than the build supports is refused.

### Workers sharing a database

A lease belongs to the **node** that created it. Every relational lease row carries the node name, and a worker reads, changes, lists and purges only rows of its own node. Startup recovery treats every non-terminal lease of its node as orphaned by a previous process, so two workers that share a database must have different node names, and a worker that is replaced keeps its node name to take its leases over. PostgreSQL and MariaDB therefore require `database.node`; a missing or empty node is a configuration error. Live takeover of one node's leases by another node is not offered.

The same node scoping applies to snapshots in an object store: a worker writes under `<prefix>snapshots/` and the profile id is unique, so two workers see each other's snapshots only when an operator points them at the same prefix on purpose (for a replacement worker).

### Secrets

Passwords, access keys and API keys are never part of a URL or an example. They come from a file named in the configuration, or from an environment variable named in this guide. A URL that carries a password is refused. A certificate authority file can be given for every network backend; without it the system roots are used. Plain-text connections are allowed only to loopback addresses unless the setting that permits them is explicit.

### Object store verification

The `self-hosted` profile is verified against both RustFS and MinIO with one contract suite, and against SeaweedFS with the snapshot-store suite. The `standard` and `edge` profiles are covered by configuration and request-signing tests: BrowserX signs requests itself (SigV4) and the signer is checked against published vectors, but no test runs against a cloud service.

## Failure behaviour

- **Lease store down.** Requests that need the registry fail with a typed storage error; `/readyz` reports not ready. Running browsers are not touched.
- **Object store down.** A snapshot write fails and is retried at the next interval; the session is unaffected. A restore that needs a snapshot fails with a typed error and the attach outcome says so (see [Recovery](recovery.md)).
- **Cache down.** The MCP server falls back to its in-memory limits and says so in `capabilities` and in the audit entry. A limit is never relaxed because the cache is unreachable.
- **Export sinks down.** The MCP audit log is written locally first. Each sink has a bounded in-memory buffer; when it is full or the sink is unreachable, records are dropped and counted (`audit_export_dropped_total` per sink), and the local chain is the source for catching up. Export is at-least-once and every exported record carries its sequence number and hash, so a receiver can check the chain and discard duplicates.

## Verification

Every backend is tested against a real service in a throwaway container: conformance suites for the lease registry and the snapshot store run unchanged on SQLite, PostgreSQL and MariaDB, and on the file store and the object store. Shared-instance tests run two namespaces (and two nodes) on one service and check they do not see each other's data. See the [Backends guide](../guides/backends.md) for how to run them.
