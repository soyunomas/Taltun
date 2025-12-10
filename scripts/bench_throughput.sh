#!/bin/bash
set -e

# Asegurar dependencias
if ! command -v iperf3 &> /dev/null; then
    echo "❌ iperf3 no está instalado. Instálalo con: sudo apt install iperf3"
    exit 1
fi
if ! command -v wget &> /dev/null; then
    echo "❌ wget no está instalado."
    exit 1
fi

BINARY="./bin/vpn"
NS_SERVER="ns-taltun-server"
NS_CLIENT="ns-taltun-client"
KEY_SERVER="1111111111111111111111111111111111111111111111111111111111111111"
KEY_CLIENT="2222222222222222222222222222222222222222222222222222222222222222"

cleanup() {
    sudo killall vpn 2>/dev/null || true
    sudo killall iperf3 2>/dev/null || true
    sudo ip netns del $NS_SERVER 2>/dev/null || true
    sudo ip netns del $NS_CLIENT 2>/dev/null || true
}
trap cleanup EXIT

echo "🚀 Configurando entorno de red (Namespaces)..."
# 1. Setup Red
sudo ip netns add $NS_SERVER
sudo ip netns add $NS_CLIENT
sudo ip link add veth-s type veth peer name veth-c
sudo ip link set veth-s netns $NS_SERVER
sudo ip link set veth-c netns $NS_CLIENT
sudo ip netns exec $NS_SERVER ip addr add 172.16.0.1/24 dev veth-s
sudo ip netns exec $NS_SERVER ip link set veth-s up
sudo ip netns exec $NS_SERVER ip link set lo up
sudo ip netns exec $NS_CLIENT ip addr add 172.16.0.2/24 dev veth-c
sudo ip netns exec $NS_CLIENT ip link set veth-c up
sudo ip netns exec $NS_CLIENT ip link set lo up

if [ ! -c /dev/net/tun ]; then sudo modprobe tun; fi

# 2. Start VPN
echo "🔌 Iniciando Nodos con Profiling activo en Server..."
# Servidor con PPROF habilitado en puerto 6060
sudo ip netns exec $NS_SERVER $BINARY \
    -mode server \
    -local "0.0.0.0:9000" \
    -tun tun0 \
    -key $KEY_SERVER \
    -vip "10.0.0.1" \
    -peer "10.0.0.2" \
    -pprof "localhost:6060" \
    > /dev/null 2>&1 &

# Cliente normal
sudo ip netns exec $NS_CLIENT $BINARY \
    -mode client \
    -local "0.0.0.0:9000" \
    -tun tun0 \
    -key $KEY_CLIENT \
    -vip "10.0.0.2" \
    -peer "10.0.0.1,172.16.0.1:9000" \
    > /dev/null 2>&1 &

sleep 2
# Configurar interfaces TUN
sudo ip netns exec $NS_SERVER ip addr add 10.0.0.1/24 dev tun0
sudo ip netns exec $NS_SERVER ip link set tun0 up
sudo ip netns exec $NS_CLIENT ip addr add 10.0.0.2/24 dev tun0
sudo ip netns exec $NS_CLIENT ip link set tun0 up
# Ajuste de MTU
sudo ip netns exec $NS_SERVER ip link set dev tun0 mtu 1420
sudo ip netns exec $NS_CLIENT ip link set dev tun0 mtu 1420

echo "⏳ Esperando Handshake..."
sleep 2

# Verificar ping rápido
if ! sudo ip netns exec $NS_CLIENT ping -c 1 10.0.0.1 > /dev/null; then
    echo "❌ La VPN no levantó. Abortando benchmark."
    exit 1
fi

echo "🔥 INICIANDO BENCHMARK (10 segundos)..."
echo "----------------------------------------"

# Iniciar iperf3 server
sudo ip netns exec $NS_SERVER iperf3 -s -1 > /dev/null &
sleep 1

# CAPTURA DE PERFIL CPU EN PARALELO
# Esperamos 2s a que iperf caliente, y grabamos 5s de perfil intenso
(
    sleep 2
    echo "📸 Capturando perfil CPU del servidor..."
    sudo ip netns exec $NS_SERVER wget -q -O cpu.prof "http://localhost:6060/debug/pprof/profile?seconds=5"
    echo "✅ Perfil guardado en cpu.prof"
) &

# Iniciar iperf3 client (Tráfico real)
sudo ip netns exec $NS_CLIENT iperf3 -c 10.0.0.1 -t 10 -P 4

echo "----------------------------------------"
echo "✅ Benchmark finalizado."
echo "💡 Analiza el perfil con: go tool pprof -top cpu.prof"
