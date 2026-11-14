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
  docker.io/library/postgres:18@sha256:b9f6b8ff03b62f3cfd9d9ba3fe56226a9991c79d3fb46fd46536263bf02be553
  docker.io/library/mariadb:11.8@sha256:d36f18d65a0459510b8b0f643b226a6d299e3206486e2b64ff20754a6d291707
  docker.io/valkey/valkey:8.1.3-alpine@sha256:d827e7f7552cdee40cc7482dbae9da020f42bc47669af6f71182a4ef76a22773
  docker.io/library/redis:8-alpine@sha256:7958cfbb9d152f87dadfbc89f1b0b15938f0b81ff8982feb327476f4911935c3
  docker.io/chrislusf/seaweedfs:latest@sha256:ccad23e18639c8b98cee17e7100b95830a06077b56d8e5b006d6dcf8ec5e94a0
  docker.io/bitnamilegacy/minio@sha256:b3d51900e846b92f7503ca6be07d2e8c56ebb6a13a60bc71b8777c716c074bcf
  docker.io/rustfs/rustfs@sha256:ecbf4480ae142703b50e5fe7e73c2c3472a270fa73d26ff62419bbc8929679c4
  docker.io/clickhouse/clickhouse-server:latest@sha256:4f491abc44d9f4a1747c033c35ddd5bc385521305d85ca8251ba0824ff597035
  docker.io/apache/kafka:latest@sha256:77e3df9054047a88b520d0cc46e16696d3b22022e1d580aeccd2632df6532837
  docker.io/library/rabbitmq:4-management@sha256:753099a19b577c322117f793f864b3129cbba96d40317221a69d73976e3c843c
  docker.io/opensearchproject/opensearch:2@sha256:3bfa1ec74d56928c2e018033d45c460ce2c0ea65a5cedd577de3102326c31b89
  docker.elastic.co/elasticsearch/elasticsearch:8.15.3@sha256:01c1732062b4a846c5ca687b0094b89bad0bfed00c6d71626db32fb8f3131a78
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
