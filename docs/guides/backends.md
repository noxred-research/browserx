# Backends

BrowserX runs on SQLite files and a snapshot directory with no other service. This guide shows how to move the lease registry to PostgreSQL or MariaDB, snapshots to an S3-compatible object store, and how to connect the MCP server to Valkey or Redis, ClickHouse, Kafka, RabbitMQ, OpenSearch and Elasticsearch. Read the [design page](../design/backends.md) first for what each family is for and what sharing a service means.

## What goes where

| You want | Configure | File |
| --- | --- | --- |
| Leases in PostgreSQL or MariaDB | `[database]` | worker configuration |
| Snapshots in an object store | `[object_store]` | worker configuration |
| One rate limit and call budget across several MCP servers | `[cache]` | MCP configuration |
| Audit records in ClickHouse | `[analytics]` | MCP configuration |
| Audit records in Kafka or RabbitMQ | `[events]` | MCP configuration |
| Audit records searchable in OpenSearch or Elasticsearch | `[search]` | MCP configuration |

Secrets (passwords, access keys, API keys) are read from files or environment variables, never from the configuration text. Prefer files: browsers do not inherit the worker's environment, but the worker's own `/proc/<pid>/environ` still holds what it read from the environment, and it cannot scrub it (see [SECURITY.md](../../SECURITY.md#what-browserx-handles)). A URL that contains a password is refused. Unknown keys are refused. A backend that is configured but cannot be used at startup is an error, except where this page says the server degrades (the cache) or drops and counts (the audit sinks).

## Relational: `[database]`

```toml
[database]
url = "postgres://browserx@db.example.test:5432/platform"   # postgres://, mysql:// (MariaDB) or sqlite:///path
schema = "browserx"                                     # PostgreSQL schema, or MariaDB database
node = "worker-eu-1"                                    # required for PostgreSQL and MariaDB
password_file = "/etc/browserx/db.password"             # or BROWSERX_DATABASE_PASSWORD
pool_size = 8
tls = "require"                                         # disable | prefer | require
tls_ca_file = "/etc/browserx/db-ca.pem"                 # optional
```

- Without `[database]`, BrowserX uses `storage.state_dir/browserx.db` as before. With `url = "sqlite:///path"` it uses that file; `schema`, `node` and the network keys are refused for SQLite.
- `schema` defaults to `browserx`. BrowserX creates the schema (PostgreSQL) or the database (MariaDB) if it is missing, and every table, including `schema_migrations`, lives inside it. Give the account `CREATE` on the database, or create the schema yourself and give the account `USAGE` and `CREATE` on it.
- `node` names this worker. Leases carry it and a worker only sees its own. Two workers must never share a node name; a replacement worker keeps the name of the one it replaces. See [Workers sharing a database](../design/backends.md#workers-sharing-a-database).
- Migrations run at startup under a lock, so several workers can start at once. A database written by a newer BrowserX is refused.
- `/readyz` fails while the database does not answer.

## Object store: `[object_store]`

```toml
[object_store]
profile = "self-hosted"          # standard | edge | self-hosted | compatible
endpoint = "https://objects.internal:9000"
region = "us-east-1"
bucket = "platform-state"
prefix = "browserx/"             # default
path_style = true
credentials_file = "/etc/browserx/objects.credentials"   # access_key_id / secret_access_key
sse = "aes256"                   # none | aes256 | kms (with kms_key_id); not on `edge`
```

| Profile | For | Defaults |
| --- | --- | --- |
| `standard` | the original S3 service | `region` required, `endpoint` optional, virtual-host addressing |
| `edge` | an edge object store with an S3 API | `endpoint` required, `region = "auto"`, path style; no `kms` |
| `self-hosted` | a self-hosted S3 service such as RustFS or MinIO | `endpoint` required, `region = "us-east-1"`, path style; plain `http://` only with `allow_http = true` or on loopback |
| `compatible` | any other S3 API | `endpoint`, `region` and `path_style` all explicit |

The credentials file holds `access_key_id = "..."` and `secret_access_key = "..."` (and optionally `session_token`). Without a file, `BROWSERX_OBJECT_STORE_ACCESS_KEY_ID` and `BROWSERX_OBJECT_STORE_SECRET_ACCESS_KEY` are used. Only sealed snapshots are stored: the snapshot key never leaves the worker, and the store sees ciphertext. BrowserX reads, writes and deletes only under `prefix` (an empty prefix is refused), so one bucket can hold several products. `tls_ca_file` adds a certificate authority to the built-in roots. A conditional create (`If-None-Match`) keeps two writers from storing the same snapshot version; a service that rejects the header falls back to a check-then-write.

## Cache: `[cache]` (MCP)

```toml
[cache]
url = "rediss://cache.internal:6379"
key_prefix = "browserx:"
db = 0
username = "browserx"
password_file = "/etc/browserx/cache.password"    # or BROWSERX_CACHE_PASSWORD
# required = true      # refuse to start when the cache does not answer (default: start degraded)
# tls_ca_file = "/etc/browserx/cache-ca.pem"
```

With a cache, the per-tool rate limits (`limits.per_minute`) and the manifest's `limits.max_calls` and `limits.rps` are counted in Valkey or Redis, so several MCP servers share one budget. If the cache cannot be reached, each server falls back to its own in-memory counters: limits are never relaxed. `capabilities` shows whether the cache is healthy or degraded. BrowserX uses only keys under `key_prefix`, never `FLUSHALL`, `FLUSHDB` or `KEYS *`.

## Audit export: `[analytics]`, `[events]`, `[search]` (MCP)

The local hash-chained audit file stays the authoritative record. Each enabled sink receives a copy of every record after it is written locally, with its sequence number and hash, so a receiver can verify the chain and drop duplicates. Delivery is at-least-once with a bounded in-memory buffer per sink; when a sink is down or slow, records are dropped and counted, and the tool call is never delayed. `capabilities` reports `sent`, `dropped`, `queued` and the last error of each sink.

```toml
[analytics]                       # ClickHouse over HTTP
url = "http://clickhouse.internal:8123"
database = "browserx"
user = "browserx"
password_file = "/etc/browserx/analytics.password"

[events]                          # kafka | amqp | none
kind = "kafka"
brokers = ["kafka-1.internal:9092"]
topic_prefix = "browserx."        # topic: browserx.audit (create it first)

[search]                          # opensearch | elasticsearch
kind = "opensearch"
url = "https://search.internal:9200"
index_prefix = "browserx-"        # index browserx-audit-v1, alias browserx-audit
api_key_file = "/etc/browserx/search.key"
```

For RabbitMQ use `kind = "amqp"` with `url`, `vhost`, `username`, `password_file` and `exchange_prefix = "browserx."`; BrowserX declares the durable topic exchange `browserx.audit` in that virtual host and publishes with confirms. Kafka topics are not created by BrowserX (create `<topic_prefix>audit` first); SASL (`plain`, `scram-sha-256`, `scram-sha-512`) and TLS are supported, and delivery is at-least-once without an idempotent producer, so use `seq` and `hash` (also sent as message headers) to deduplicate. ClickHouse keeps the full record in a `raw` column next to typed columns. Search documents use the record hash as their id, so a retry does not duplicate. `api_key_file` is for Elasticsearch; OpenSearch uses basic authentication. For OpenSearch and Elasticsearch, BrowserX detects the engine and version at startup, refuses a mismatch with `kind`, and touches only indices that start with `index_prefix`.

## Sharing one set of services

Several BrowserX workers, and other tools, can use the same instances. Give each product its own namespace and each BrowserX worker its own node:

| Service | Per product | Per BrowserX worker |
| --- | --- | --- |
| PostgreSQL / MariaDB | `schema` (default `browserx`) | `node` |
| Object store | `bucket` + `prefix` (default `browserx/`) | same prefix; profile ids are unique |
| Valkey / Redis | `key_prefix` (default `browserx:`), `db`, ACL user | shared on purpose (budgets) |
| ClickHouse | `database` (default `browserx`) | shared |
| Kafka / RabbitMQ | `topic_prefix` / `vhost` and `exchange_prefix` | shared |
| OpenSearch / Elasticsearch | `index_prefix` (default `browserx-`) | shared |

Give each product its own account where the service has accounts, limited to its namespace. BrowserX never writes outside its namespace, but an account that can is a risk you can remove.

## Running the backend tests

The tests start throwaway containers with podman, publish their ports on loopback only and remove them afterwards. They run only when `BROWSERX_TEST_SERVICES=1`; otherwise they print `SKIP:` and pass.

```sh
ci/run-backend-tests.sh        # pulls the images, runs the service tests, fails if any was skipped
```

Set `BROWSERX_REQUIRE_SERVICES=1` to make a missing podman or a container that does not start a failure instead of a skip. Images used: PostgreSQL, MariaDB, Valkey, Redis, ClickHouse, Kafka, RabbitMQ, OpenSearch, Elasticsearch and three self-hosted S3 servers: RustFS and MinIO (pinned by digest; MinIO from the `bitnamilegacy` mirror because upstream images are no longer published) run the same contract suite, and SeaweedFS is exercised by the snapshot-store suite. The contract covers credentials from a file, path-style addressing, prefix isolation between two products in one bucket, list pagination over 1000 keys, delete, an 8 MiB object and wrong-credential refusal; multipart upload is not used because each sealed snapshot is one request. The worker test (`browserx-server`, `--test backends`) also needs a Chromium. The `standard` and `edge` object-store profiles are covered by configuration and request-signing tests, not by a real cloud service.
