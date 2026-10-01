#!/usr/bin/env bash
set -euo pipefail

if [[ "${EUID}" -ne 0 ]]; then
  echo "run_integration_test.sh must run as root (use sudo)" >&2
  exit 1
fi

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
BIN="${ROOT_DIR}/bin/vpn"
KEYGEN="${ROOT_DIR}/bin/taltun-keygen"
TMP="$(mktemp -d)"
BR="br-taltun-ci"
NS_HUB="ns-taltun-hub"
NS_A="ns-taltun-a"
NS_B="ns-taltun-b"
PIDS=()

cleanup() {
  set +e
  for pid in "${PIDS[@]:-}"; do
    kill "${pid}" 2>/dev/null || true
  done
  wait 2>/dev/null || true
  for ns in "${NS_HUB}" "${NS_A}" "${NS_B}"; do
    ip netns del "${ns}" 2>/dev/null || true
  done
  ip link del "${BR}" 2>/dev/null || true
  rm -rf "${TMP}"
}
trap cleanup EXIT

for cmd in ip ping sed grep; do
  command -v "${cmd}" >/dev/null || { echo "missing dependency: ${cmd}" >&2; exit 1; }
done

mkdir -p "${ROOT_DIR}/bin"
go build -o "${BIN}" ./cmd/vpn
go build -o "${KEYGEN}" ./cmd/keygen

if [[ ! -c /dev/net/tun ]]; then
  modprobe tun || true
fi
[[ -c /dev/net/tun ]] || { echo "/dev/net/tun is unavailable" >&2; exit 1; }

make_pair() {
  local prefix="$1" out priv pub
  out="$("${KEYGEN}")"
  priv="$(printf '%s\n' "${out}" | sed -n 's/^private_key = "\([0-9a-f]*\)"$/\1/p')"
  pub="$(printf '%s\n' "${out}" | sed -n 's/^public_key = "\([0-9a-f]*\)"$/\1/p')"
  [[ -n "${priv}" && -n "${pub}" ]] || { echo "keygen parse failed" >&2; exit 1; }
  printf -v "${prefix}_PRIV" '%s' "${priv}"
  printf -v "${prefix}_PUB" '%s' "${pub}"
}
make_pair HUB
make_pair A
make_pair B

ip link add "${BR}" type bridge
ip link set "${BR}" up

create_ns() {
  local ns="$1" host_if="$2" addr="$3"
  ip netns add "${ns}"
  ip link add "${host_if}" type veth peer name eth0
  ip link set eth0 netns "${ns}"
  ip link set "${host_if}" master "${BR}"
  ip link set "${host_if}" up
  ip netns exec "${ns}" ip link set lo up
  ip netns exec "${ns}" ip addr add "${addr}/24" dev eth0
  ip netns exec "${ns}" ip link set eth0 up
}

create_ns "${NS_HUB}" veth-hub 172.16.0.1
create_ns "${NS_A}" veth-a 172.16.0.2
create_ns "${NS_B}" veth-b 172.16.0.3

# Simulated LAN behind peer A.
ip netns exec "${NS_A}" ip addr add 192.168.50.10/32 dev lo

cat >"${TMP}/hub.toml" <<EOF
[interface]
mode = "server"
local_addr = "172.16.0.1:9000"
tun_name = "tun0"
private_key = "${HUB_PRIV}"
vip = "10.0.0.1"
mtu = 1380
routes = ["10.0.0.0/24"]

[[peers]]
vip = "10.0.0.2"
public_key = "${A_PUB}"
allowed_ips = ["192.168.50.0/24"]

[[peers]]
vip = "10.0.0.3"
public_key = "${B_PUB}"
EOF

cat >"${TMP}/a.toml" <<EOF
[interface]
mode = "client"
local_addr = "172.16.0.2:9000"
tun_name = "tun0"
private_key = "${A_PRIV}"
vip = "10.0.0.2"
mtu = 1380
routes = ["10.0.0.0/24"]

[[peers]]
vip = "10.0.0.1"
public_key = "${HUB_PUB}"
endpoint = "172.16.0.1:9000"
allowed_ips = ["10.0.0.0/24"]
EOF

cat >"${TMP}/b.toml" <<EOF
[interface]
mode = "client"
local_addr = "172.16.0.3:9000"
tun_name = "tun0"
private_key = "${B_PRIV}"
vip = "10.0.0.3"
mtu = 1380
routes = ["10.0.0.0/24", "192.168.50.0/24"]

[[peers]]
vip = "10.0.0.1"
public_key = "${HUB_PUB}"
endpoint = "172.16.0.1:9000"
allowed_ips = ["10.0.0.0/24", "192.168.50.0/24"]
EOF

start_node() {
  local ns="$1" cfg="$2" log="$3" __pidvar="$4"
  ip netns exec "${ns}" "${BIN}" -config "${cfg}" -debug >"${log}" 2>&1 &
  local pid=$!
  PIDS+=("${pid}")
  printf -v "${__pidvar}" '%s' "${pid}"
}

wait_ping() {
  local ns="$1" target="$2" label="$3"
  for _ in $(seq 1 30); do
    if ip netns exec "${ns}" ping -c 1 -W 1 "${target}" >/dev/null 2>&1; then
      echo "PASS: ${label}"
      return 0
    fi
    sleep 1
  done
  echo "FAIL: ${label}" >&2
  echo "--- hub.log ---" >&2; tail -n 80 "${TMP}/hub.log" >&2 || true
  echo "--- a.log ---" >&2; tail -n 80 "${TMP}/a.log" >&2 || true
  echo "--- b.log ---" >&2; tail -n 80 "${TMP}/b.log" >&2 || true
  return 1
}

start_node "${NS_HUB}" "${TMP}/hub.toml" "${TMP}/hub.log" PID_HUB
start_node "${NS_A}" "${TMP}/a.toml" "${TMP}/a.log" PID_A
start_node "${NS_B}" "${TMP}/b.toml" "${TMP}/b.log" PID_B

wait_ping "${NS_A}" 10.0.0.1 "client A -> hub"
wait_ping "${NS_A}" 10.0.0.3 "client A -> client B relay"
wait_ping "${NS_B}" 192.168.50.10 "client B -> LAN behind client A"

# Restart B while hub/A stay alive. The restarted process begins counters at 1
# under a new ephemeral session and must recover without stale replay state.
kill "${PID_B}"
wait "${PID_B}" || true
start_node "${NS_B}" "${TMP}/b.toml" "${TMP}/b-restart.log" PID_B2
wait_ping "${NS_A}" 10.0.0.3 "relay after client B restart"
wait_ping "${NS_B}" 192.168.50.10 "subnet routing after client B restart"

# End-to-end rekey: wait beyond the default 2 minute interval and prove traffic
# still flows after a new authenticated ephemeral session is installed.
echo "waiting for automatic rekey..."
sleep 125
wait_ping "${NS_A}" 10.0.0.3 "relay after automatic rekey"
wait_ping "${NS_B}" 192.168.50.10 "subnet routing after automatic rekey"

# At least one node should have installed more than its initial session.
sessions="$(grep -h -c 'Sesión v2' "${TMP}/hub.log" "${TMP}/a.log" "${TMP}/b-restart.log" | awk '{s+=$1} END {print s+0}')"
if [[ "${sessions}" -lt 5 ]]; then
  echo "FAIL: expected multiple session-v2 installations across restart/rekey, saw ${sessions}" >&2
  exit 1
fi

echo "PASS: integration suite complete"
