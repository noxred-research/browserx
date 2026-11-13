#!/usr/bin/env bash
# Runs the backend integration tests against real services in throwaway podman containers.
#
# Usage: ci/run-backend-tests.sh
#
# The tests start PostgreSQL, MariaDB, Valkey, Redis, S3-compatible stores (MinIO, RustFS and
# SeaweedFS), ClickHouse, Kafka,
# RabbitMQ, OpenSearch and Elasticsearch, each in a container with a unique name, ports on
# loopback and data on tmpfs, and remove them afterwards. This script pulls the images first,
# refuses to start without podman, sets BROWSERX_TEST_SERVICES=1 and BROWSERX_REQUIRE_SERVICES=1
# (a missing service is a failure) and fails when the output carries a `SKIP:` note.
set -euo pipefail

if ! command -v podman >/dev/null 2>&1; then
  echo "podman is required to run the backend tests" >&2
  exit 2
fi

images=(
  docker.io/library/postgres:18
  docker.io/library/mariadb:11.8
  docker.io/valkey/valkey:8.1.3-alpine
  docker.io/library/redis:8-alpine
  docker.io/chrislusf/seaweedfs:latest
  docker.io/bitnamilegacy/minio@sha256:b3d51900e846b92f7503ca6be07d2e8c56ebb6a13a60bc71b8777c716c074bcf
  docker.io/rustfs/rustfs@sha256:ecbf4480ae142703b50e5fe7e73c2c3472a270fa73d26ff62419bbc8929679c4
  docker.io/clickhouse/clickhouse-server:latest
  docker.io/apache/kafka:latest
  docker.io/library/rabbitmq:4-management
  docker.io/opensearchproject/opensearch:2
  docker.elastic.co/elasticsearch/elasticsearch:8.15.3
)
for image in "${images[@]}"; do
  podman image exists "$image" || podman pull --quiet "$image" >/dev/null
done

export BROWSERX_TEST_SERVICES=1 BROWSERX_REQUIRE_SERVICES=1
log="$(mktemp)"
cleanup() {
  rm -f "$log"
  # Containers remove themselves when their test ends; this catches a killed test run.
  podman ps -aq --filter label=bx-test=1 | xargs -r podman rm -f -t 0 >/dev/null 2>&1 || true
}
trap cleanup EXIT

export BROWSERX_CHROMIUM_PATH="${BROWSERX_CHROMIUM_PATH:-$(command -v chromium chromium-browser 2>/dev/null | head -n1)}"
{
  cargo test --locked --no-fail-fast -p browserx-store -p browserx-mcp -- --nocapture --test-threads=2
  # The worker on PostgreSQL and an object store needs a real browser; without one it skips.
  cargo test --locked --no-fail-fast -p browserx-server --test backends -- --nocapture
} 2>&1 | tee "$log"

if grep -Eq '(^|[[:space:]])SKIP: .*(service|podman|container)' "$log"; then
  echo "a backend test skipped although services are required" >&2
  exit 1
fi
