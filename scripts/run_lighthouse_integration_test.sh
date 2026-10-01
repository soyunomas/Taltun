#!/usr/bin/env bash
set -euo pipefail

if [[ "${EUID}" -ne 0 ]]; then
  echo "run_lighthouse_integration_test.sh must run as root" >&2
  exit 1
fi

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
BIN="${ROOT_DIR}/bin/vpn"
KEYGEN="${ROOT_DIR}/bin/taltun-keygen"
TMP="$(mktemp -d)"

NS_LH="ns-taltun-lh"
NS_NAT_A="ns-taltun-nat-a"
NS_A="ns-taltun-lh-a"
NS_NAT_B="ns-taltun-nat-b"
NS_B="ns-taltun-lh-b"
BR_EXT="br-taltun-ext"
PIDS=()

cleanup() {
  set +e
  for pid in "${PIDS[@]:-}"; do
    kill "${pid}" 2>/dev/null || true
  done
  wait 2>/dev/null || true
  for ns in "${NS_LH}" "${NS_NAT_A}" "${NS_A}" "${NS_NAT_B}" "${NS_B}"; do
    ip netns del "${ns}" 2>/dev/null || true
  done
  ip link del "${BR_EXT}" 2>/dev/null || true
  rm -rf "${TMP}"
}
trap cleanup EXIT

for cmd in ip ping iptables sed grep awk; do
  command -v "${cmd}" >/dev/null || { echo "missing dependency: ${cmd}" >&2; exit 1; }
done

mkdir -p "${ROOT_DIR}/bin"
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
make_pair LH
make_pair A
make_pair B

ip link add "${BR_EXT}" type bridge
ip link set "${BR_EXT}" up

attach_external() {
  local ns="$1" host_if="$2" ns_if="$3" addr="$4"
  ip netns add "${ns}"
  ip link add "${host_if}" type veth peer name "${ns_if}"
  ip link set "${ns_if}" netns "${ns}"
  ip link set "${host_if}" master "${BR_EXT}"
  ip link set "${host_if}" up
  ip netns exec "${ns}" ip link set lo up
  ip netns exec "${ns}" ip addr add "${addr}/24" dev "${ns_if}"
  ip netns exec "${ns}" ip link set "${ns_if}" up
}

attach_external "${NS_LH}" lh-host lh-ext 203.0.113.1
attach_external "${NS_NAT_A}" nata-host ext0 203.0.113.2
attach_external "${NS_NAT_B}" natb-host ext0 203.0.113.3

create_inside() {
  local natns="$1" clientns="$2" nat_if="$3" client_if="$4" nat_addr="$5" client_addr="$6"
  ip netns add "${clientns}"
  ip link add "${nat_if}" type veth peer name "${client_if}"
  ip link set "${nat_if}" netns "${natns}"
  ip link set "${client_if}" netns "${clientns}"

  ip netns exec "${natns}" ip addr add "${nat_addr}/24" dev "${nat_if}"
  ip netns exec "${natns}" ip link set "${nat_if}" up

  ip netns exec "${clientns}" ip link set lo up
  ip netns exec "${clientns}" ip addr add "${client_addr}/24" dev "${client_if}"
  ip netns exec "${clientns}" ip link set "${client_if}" up
  ip netns exec "${clientns}" ip route add default via "${nat_addr}"
}

create_inside "${NS_NAT_A}" "${NS_A}" lan0 eth0 10.10.1.1 10.10.1.2
create_inside "${NS_NAT_B}" "${NS_B}" lan0 eth0 10.20.1.1 10.20.1.2

configure_nat() {
  local ns="$1"
  ip netns exec "${ns}" sysctl -q -w net.ipv4.ip_forward=1
  ip netns exec "${ns}" iptables -P FORWARD ACCEPT
  ip netns exec "${ns}" iptables -t nat -A POSTROUTING -o ext0 -j MASQUERADE
}
configure_nat "${NS_NAT_A}"
configure_nat "${NS_NAT_B}"

cat >"${TMP}/lh.toml" <<EOF
[interface]
mode = "lighthouse"
local_addr = "203.0.113.1:9000"
private_key = "${LH_PRIV}"
vip = "10.77.0.1"
mtu = 1380
workers = 1

[[peers]]
vip = "10.77.0.2"
public_key = "${A_PUB}"

[[peers]]
vip = "10.77.0.3"
public_key = "${B_PUB}"
EOF

cat >"${TMP}/a.toml" <<EOF
[interface]
mode = "client"
local_addr = "0.0.0.0:9000"
tun_name = "tun0"
private_key = "${A_PRIV}"
vip = "10.77.0.2"
mtu = 1380
workers = 1
routes = ["10.77.0.0/24"]

[[peers]]
vip = "10.77.0.1"
public_key = "${LH_PUB}"
endpoint = "203.0.113.1:9000"
allowed_ips = ["10.77.0.0/24"]
lighthouse = true

[[peers]]
vip = "10.77.0.3"
public_key = "${B_PUB}"
EOF

cat >"${TMP}/b.toml" <<EOF
[interface]
mode = "client"
local_addr = "0.0.0.0:9000"
tun_name = "tun0"
private_key = "${B_PRIV}"
vip = "10.77.0.3"
mtu = 1380
workers = 1
routes = ["10.77.0.0/24"]

[[peers]]
vip = "10.77.0.1"
public_key = "${LH_PUB}"
endpoint = "203.0.113.1:9000"
allowed_ips = ["10.77.0.0/24"]
lighthouse = true

[[peers]]
vip = "10.77.0.2"
public_key = "${A_PUB}"
EOF

start_node() {
  local ns="$1" cfg="$2" log="$3" __pidvar="$4"
  ip netns exec "${ns}" "${BIN}" -config "${cfg}" -debug >"${log}" 2>&1 &
  local pid=$!
  PIDS+=("${pid}")
  printf -v "${__pidvar}" '%s' "${pid}"
}

wait_ping() {
  local ns="$1" target="$2" label="$3" tries="${4:-30}"
  for _ in $(seq 1 "${tries}"); do
    if ip netns exec "${ns}" ping -c 1 -W 1 "${target}" >/dev/null 2>&1; then
      echo "PASS: ${label}"
      return 0
    fi
    sleep 1
  done
  echo "FAIL: ${label}" >&2
  echo "--- lighthouse.log ---" >&2; tail -n 100 "${TMP}/lh.log" >&2 || true
  echo "--- a.log ---" >&2; tail -n 100 "${TMP}/a.log" >&2 || true
  echo "--- b.log ---" >&2; tail -n 100 "${TMP}/b.log" >&2 || true
  return 1
}

wait_log() {
  local file="$1" pattern="$2" label="$3" tries="${4:-30}"
  for _ in $(seq 1 "${tries}"); do
    if grep -q "${pattern}" "${file}"; then
      echo "PASS: ${label}"
      return 0
    fi
    sleep 1
  done
  echo "FAIL: ${label} (pattern: ${pattern})" >&2
  tail -n 120 "${file}" >&2 || true
  return 1
}

start_node "${NS_LH}" "${TMP}/lh.toml" "${TMP}/lh.log" PID_LH
start_node "${NS_A}" "${TMP}/a.toml" "${TMP}/a.log" PID_A
start_node "${NS_B}" "${TMP}/b.toml" "${TMP}/b.log" PID_B

wait_ping "${NS_A}" 10.77.0.1 "A -> Lighthouse session"
wait_ping "${NS_B}" 10.77.0.1 "B -> Lighthouse session"

# First A->B traffic must work through the Lighthouse relay because neither
# spoke starts with the other's endpoint.
wait_ping "${NS_A}" 10.77.0.3 "initial A -> B through Lighthouse relay"

# Relay traffic causes encrypted PeerUpdate messages. Both clients should then
# prove the candidate endpoint with a direct v2 handshake.
wait_log "${TMP}/a.log" 'Sesión v2 iniciada con 10.77.0.3' "A established direct v2 session to B"
wait_log "${TMP}/b.log" 'Sesión v2 aceptada con 10.77.0.2\|Sesión v2 iniciada con 10.77.0.2' "B established direct v2 session to A"

# Prove the data path is truly direct: make the Lighthouse unreachable from
# both clients while keeping A<->B public NAT addresses reachable.
ip netns exec "${NS_NAT_A}" iptables -I FORWARD 1 -p udp -d 203.0.113.1 --dport 9000 -j DROP
ip netns exec "${NS_NAT_B}" iptables -I FORWARD 1 -p udp -d 203.0.113.1 --dport 9000 -j DROP
wait_ping "${NS_A}" 10.77.0.3 "A -> B remains alive with Lighthouse blocked" 15

# Restore Lighthouse reachability, then break the direct public path in both
# directions. After DirectFallbackTimeout the /32 route must move back to the
# trusted Lighthouse and relay traffic must recover.
ip netns exec "${NS_NAT_A}" iptables -D FORWARD 1
ip netns exec "${NS_NAT_B}" iptables -D FORWARD 1

ip netns exec "${NS_NAT_A}" iptables -I FORWARD 1 -p udp -d 203.0.113.3 --dport 9000 -j DROP
ip netns exec "${NS_NAT_B}" iptables -I FORWARD 1 -p udp -d 203.0.113.2 --dport 9000 -j DROP

echo "waiting for direct-path liveness timeout..."
sleep 35
wait_log "${TMP}/a.log" 'Lighthouse fallback: 10.77.0.3 via 10.77.0.1' "A fell back to Lighthouse relay" 10
wait_ping "${NS_A}" 10.77.0.3 "A -> B works through relay after direct-path failure" 15

# Restore the direct path. Relay traffic should emit PeerUpdate again and a new
# authenticated direct session should be installed.
ip netns exec "${NS_NAT_A}" iptables -D FORWARD 1
ip netns exec "${NS_NAT_B}" iptables -D FORWARD 1

before="$(grep -c 'Sesión v2 iniciada con 10.77.0.3' "${TMP}/a.log" || true)"
for _ in $(seq 1 20); do
  ip netns exec "${NS_A}" ping -c 1 -W 1 10.77.0.3 >/dev/null 2>&1 || true
  after="$(grep -c 'Sesión v2 iniciada con 10.77.0.3' "${TMP}/a.log" || true)"
  if [[ "${after}" -gt "${before}" ]]; then
    echo "PASS: direct A -> B session recovered after relay fallback"
    break
  fi
  sleep 1
done
after="$(grep -c 'Sesión v2 iniciada con 10.77.0.3' "${TMP}/a.log" || true)"
if [[ "${after}" -le "${before}" ]]; then
  echo "FAIL: direct session was not re-established" >&2
  tail -n 120 "${TMP}/a.log" >&2
  exit 1
fi

# Block Lighthouse again: recovered direct route must carry traffic by itself.
ip netns exec "${NS_NAT_A}" iptables -I FORWARD 1 -p udp -d 203.0.113.1 --dport 9000 -j DROP
ip netns exec "${NS_NAT_B}" iptables -I FORWARD 1 -p udp -d 203.0.113.1 --dport 9000 -j DROP
wait_ping "${NS_A}" 10.77.0.3 "recovered direct path survives without Lighthouse" 15

echo "PASS: Lighthouse NAT traversal, direct promotion, fallback and recovery complete"
