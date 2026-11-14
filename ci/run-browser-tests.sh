#!/usr/bin/env bash
# Runs the real-browser tests against a Chromium executable chosen by the operator.
#
# Usage: ci/run-browser-tests.sh /absolute/path/to/chromium
#
# The tests look for a browser in BROWSERX_CHROMIUM_PATH first and skip with a printed note when
# they find none. This script makes a skip impossible: it refuses to start unless the path is an
# executable that reports a version, exports it, and fails when the output carries a Chromium `SKIP:`
# note. Notes of the service-backed tests (they need podman, see ci/run-backend-tests.sh) are not
# browser skips and do not fail this script.
set -euo pipefail

chromium="${1:-}"
if [ -z "$chromium" ]; then
  echo "usage: $0 /absolute/path/to/chromium" >&2
  exit 2
fi
case "$chromium" in
  /*) ;;
  *) echo "the Chromium path must be absolute: $chromium" >&2; exit 2 ;;
esac
if [ ! -x "$chromium" ]; then
  echo "not an executable file: $chromium" >&2
  exit 2
fi
"$chromium" --version

export BROWSERX_CHROMIUM_PATH="$chromium"
log="$(mktemp)"
trap 'rm -f "$log"' EXIT

cargo test --workspace --locked --no-fail-fast -- --nocapture 2>&1 | tee "$log"

if grep -Eq '(^|[[:space:]])SKIP: no Chromium' "$log"; then
  echo "a real-browser test skipped although BROWSERX_CHROMIUM_PATH is set" >&2
  exit 1
fi
