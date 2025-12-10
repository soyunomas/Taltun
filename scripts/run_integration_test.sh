#!/bin/bash
set -e

# Colores
GREEN='\033[0;32m'
RED='\033[0;31m'
NC='\033[0m'

BINARY="./bin/vpn"
NS_SERVER="ns-taltun-server"
NS_CLIENT="ns-taltun-client"

cleanup() {
    echo -e "${GREEN}[*] Limpiando procesos...${NC}"
    sudo killall vpn 2>/dev/null || true
    sudo ip netns del $NS_SERVER 2>/dev/null || true
    sudo ip netns del $NS_CLIENT 2>/dev/null || true
}
trap cleanup EXIT

if ! lsmod | grep -q "^tun"; then
    echo "⚠️ Módulo 'tun' no cargado. Cargando..."
    sudo modprobe tun
fi

KEY_SERVER="1111111111111111111111111111111111111111111111111111111111111111"
KEY_CLIENT="2222222222222222222222222222222222222222222222222222222222222222"

echo -e "${GREEN}[*] Compilando...${NC}"
go build -ldflags="-s -w" -o $BINARY ./cmd/vpn

echo -e "${GREEN}[*] Setup Network Namespace...${NC}"
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

if [ ! -c /dev/net/tun ]; then
    echo -e "${RED}❌ /dev/net/tun error.${NC}"
    exit 1
fi

echo -e "${GREEN}[*] Start Server (VIP 10.0.0.1)...${NC}"
# Agregado -debug y -vip
sudo ip netns exec $NS_SERVER $BINARY \
    -mode server \
    -local "0.0.0.0:9000" \
    -tun tun0 \
    -key $KEY_SERVER \
    -vip "10.0.0.1" \
    -peer "10.0.0.2" \
    -debug > server.log 2>&1 &
PID_SERVER=$!

sleep 1
if ! ps -p $PID_SERVER > /dev/null; then
    echo -e "${RED}❌ Server died:${NC}"
    cat server.log
    exit 1
fi

sudo ip netns exec $NS_SERVER ip addr add 10.0.0.1/24 dev tun0
sudo ip netns exec $NS_SERVER ip link set tun0 up

echo -e "${GREEN}[*] Start Client (VIP 10.0.0.2)...${NC}"
# Agregado -debug y -vip
sudo ip netns exec $NS_CLIENT $BINARY \
    -mode client \
    -local "0.0.0.0:9000" \
    -tun tun0 \
    -key $KEY_CLIENT \
    -vip "10.0.0.2" \
    -peer "10.0.0.1,172.16.0.1:9000" \
    -debug > client.log 2>&1 &
PID_CLIENT=$!

sleep 1
if ! ps -p $PID_CLIENT > /dev/null; then
    echo -e "${RED}❌ Client died:${NC}"
    cat client.log
    exit 1
fi

sudo ip netns exec $NS_CLIENT ip addr add 10.0.0.2/24 dev tun0
sudo ip netns exec $NS_CLIENT ip link set tun0 up

echo -e "${GREEN}[*] Ping Test...${NC}"
sleep 3 # Damos un segundo extra para el handshake

if sudo ip netns exec $NS_CLIENT ping -c 3 -i 0.2 10.0.0.1; then
    echo -e "${GREEN}✅ EXITO: Handshake & Data flow OK.${NC}"
    echo "--- Handshake Info ---"
    grep "Handshake" server.log | head -n 5
else
    echo -e "${RED}❌ Fail.${NC}"
    echo "--- Server Log (Last 20 lines) ---"
    tail -n 20 server.log
    echo "--- Client Log (Last 20 lines) ---"
    tail -n 20 client.log
    exit 1
fi
