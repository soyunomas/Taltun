#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
echo "benchmark_iperf.sh is retained as a compatibility alias."
echo "Using the canonical reproducible harness: scripts/bench_throughput.sh"
exec "${ROOT_DIR}/scripts/bench_throughput.sh" "$@"
