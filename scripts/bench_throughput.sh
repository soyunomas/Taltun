#!/usr/bin/env bash
set -euo pipefail

if [[ "${EUID}" -ne 0 ]]; then
  echo "bench_throughput.sh must run as root" >&2
  exit 1
fi

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
BIN="${ROOT_DIR}/bin/vpn"
KEYGEN="${ROOT_DIR}/bin/taltun-keygen"
OUT_DIR="${BENCH_OUT:-${ROOT_DIR}/benchmark-results}"
WORKERS="${WORKERS:-0}"
NS_S="ns-taltun-perf-s"
NS_C="ns-taltun-perf-c"
TMP="$(mktemp -d)"
PID_S=""
PID_C=""

cleanup() {
  set +e
  [[ -n "${PID_S}" ]] && kill "${PID_S}" 2>/dev/null || true
  [[ -n "${PID_C}" ]] && kill "${PID_C}" 2>/dev/null || true
  ip netns del "${NS_S}" 2>/dev/null || true
  ip netns del "${NS_C}" 2>/dev/null || true
  rm -rf "${TMP}"
}
trap cleanup EXIT

for cmd in ip iperf3 jq curl ping sed awk; do
  command -v "${cmd}" >/dev/null || { echo "missing dependency: ${cmd}" >&2; exit 1; }
done

mkdir -p "${ROOT_DIR}/bin" "${OUT_DIR}"
go build -o "${BIN}" ./cmd/vpn
go build -o "${KEYGEN}" ./cmd/keygen

if [[ ! -c /dev/net/tun ]]; then
  modprobe tun || true
fi
[[ -c /dev/net/tun ]] || { echo "/dev/net/tun unavailable" >&2; exit 1; }

make_pair() {
  local prefix="$1" out priv pub
  out="$("${KEYGEN}")"
  priv="$(printf '%s\n' "${out}" | sed -n 's/^private_key = "\([0-9a-f]*\)"$/\1/p')"
  pub="$(printf '%s\n' "${out}" | sed -n 's/^public_key = "\([0-9a-f]*\)"$/\1/p')"
  [[ -n "${priv}" && -n "${pub}" ]] || { echo "keygen parse failed" >&2; exit 1; }
  printf -v "${prefix}_PRIV" '%s' "${priv}"
  printf -v "${prefix}_PUB" '%s' "${pub}"
}
make_pair SERVER
make_pair CLIENT

ip netns add "${NS_S}"
ip netns add "${NS_C}"
ip link add perf-s type veth peer name perf-c
ip link set perf-s netns "${NS_S}"
ip link set perf-c netns "${NS_C}"
ip netns exec "${NS_S}" ip addr add 192.0.2.1/24 dev perf-s
ip netns exec "${NS_S}" ip link set perf-s up
ip netns exec "${NS_S}" ip link set lo up
ip netns exec "${NS_C}" ip addr add 192.0.2.2/24 dev perf-c
ip netns exec "${NS_C}" ip link set perf-c up
ip netns exec "${NS_C}" ip link set lo up

cat >"${TMP}/server.toml" <<EOF
[interface]
mode = "server"
local_addr = "192.0.2.1:9000"
tun_name = "tun0"
private_key = "${SERVER_PRIV}"
vip = "10.99.0.1"
mtu = 1380
workers = ${WORKERS}
routes = ["10.99.0.0/24"]

[[peers]]
vip = "10.99.0.2"
public_key = "${CLIENT_PUB}"
EOF

cat >"${TMP}/client.toml" <<EOF
[interface]
mode = "client"
local_addr = "192.0.2.2:9000"
tun_name = "tun0"
private_key = "${CLIENT_PRIV}"
vip = "10.99.0.2"
mtu = 1380
workers = ${WORKERS}
routes = ["10.99.0.0/24"]

[[peers]]
vip = "10.99.0.1"
public_key = "${SERVER_PUB}"
endpoint = "192.0.2.1:9000"
EOF

ip netns exec "${NS_S}" "${BIN}" -config "${TMP}/server.toml" -pprof "127.0.0.1:6060" >"${OUT_DIR}/server.log" 2>&1 &
PID_S=$!
ip netns exec "${NS_C}" "${BIN}" -config "${TMP}/client.toml" >"${OUT_DIR}/client.log" 2>&1 &
PID_C=$!

for _ in $(seq 1 30); do
  if ip netns exec "${NS_C}" ping -c 1 -W 1 10.99.0.1 >/dev/null 2>&1; then
    break
  fi
  sleep 1
done
ip netns exec "${NS_C}" ping -c 1 -W 1 10.99.0.1 >/dev/null

ip netns exec "${NS_S}" iperf3 -s -D
sleep 1

(
  ip netns exec "${NS_S}" curl -fsS "http://127.0.0.1:6060/debug/pprof/profile?seconds=5" >"${OUT_DIR}/cpu.prof"
) &
PROFILE_PID=$!

ip netns exec "${NS_C}" iperf3 -c 10.99.0.1 -t 10 -P 4 -J >"${OUT_DIR}/tcp.json"
wait "${PROFILE_PID}"

ip netns exec "${NS_C}" iperf3 -c 10.99.0.1 -u -b 1G -t 5 -J >"${OUT_DIR}/udp.json"
ip netns exec "${NS_C}" ping -c 20 -i 0.05 10.99.0.1 >"${OUT_DIR}/ping.txt"

TCP_BPS="$(jq -r '.end.sum_received.bits_per_second // .end.sum_sent.bits_per_second // 0' "${OUT_DIR}/tcp.json")"
UDP_BPS="$(jq -r '.end.sum.bits_per_second // 0' "${OUT_DIR}/udp.json")"
UDP_LOSS="$(jq -r '.end.sum.lost_percent // 0' "${OUT_DIR}/udp.json")"
UDP_PACKETS="$(jq -r '.end.sum.packets // 0' "${OUT_DIR}/udp.json")"
PING_AVG="$(awk -F'=' '/^rtt|^round-trip/ {gsub(/ /,"",$2); split($2,a,"/"); print a[2]}' "${OUT_DIR}/ping.txt")"
CPU_COUNT="$(nproc)"
EFFECTIVE_WORKERS="${WORKERS}"
if [[ "${WORKERS}" -eq 0 ]]; then EFFECTIVE_WORKERS="${CPU_COUNT}"; fi

jq -n   --arg commit "${GITHUB_SHA:-unknown}"   --arg kernel "$(uname -r)"   --argjson cpu_count "${CPU_COUNT}"   --argjson workers "${EFFECTIVE_WORKERS}"   --argjson tcp_bps "${TCP_BPS}"   --argjson udp_bps "${UDP_BPS}"   --argjson udp_loss_percent "${UDP_LOSS}"   --argjson udp_packets "${UDP_PACKETS}"   --arg ping_avg_ms "${PING_AVG:-unknown}"   '{
    commit: $commit,
    kernel: $kernel,
    cpu_count: $cpu_count,
    workers: $workers,
    tcp_bits_per_second: $tcp_bps,
    udp_bits_per_second: $udp_bps,
    udp_loss_percent: $udp_loss_percent,
    udp_packets: $udp_packets,
    ping_avg_ms: $ping_avg_ms,
    methodology: {
      mtu: 1380,
      tcp_seconds: 10,
      tcp_streams: 4,
      udp_seconds: 5,
      udp_target_bps: 1000000000,
      ping_samples: 20,
      transport: "Linux network namespaces + veth",
      profile_seconds: 5
    }
  }' >"${OUT_DIR}/benchmark.json"

cat "${OUT_DIR}/benchmark.json"
