#!/bin/bash

# ==========================================
# GOpt Expert: VPN Throughput Benchmark (iPerf3) [FIXED]
# ==========================================

GREEN='\033[0;32m'
RED='\033[0;31m'
BLUE='\033[0;34m'
YELLOW='\033[1;33m'
NC='\033[0m'

KEY="aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
BIN="./bin/vpn"
NS_S="ns_perf_srv"
NS_C="ns_perf_cli"

# IPs Transporte (Simulación Internet)
PUB_IP_S="192.168.99.1"
PUB_IP_C="192.168.99.2"

# IPs Túnel
VPN_IP_S="10.99.0.1"
VPN_IP_C="10.99.0.2"

# Chequeo de dependencia
if ! command -v iperf3 &> /dev/null; then
    echo -e "${RED}Error: iperf3 no está instalado.${NC}"
    echo "Instálalo con: sudo apt install iperf3"
    exit 1
fi

cleanup() {
    echo -e "\n${BLUE}🧹 Limpiando laboratorio...${NC}"
    killall iperf3 2>/dev/null
    pkill -F server.pid 2>/dev/null
    pkill -F client.pid 2>/dev/null
    rm -f server.pid client.pid
    
    ip netns delete $NS_S 2>/dev/null
    ip netns delete $NS_C 2>/dev/null
    
    # NO borramos logs para poder debuguear
    echo -e "📝 Logs disponibles: $(pwd)/server.log y $(pwd)/client.log"
}
trap cleanup EXIT

echo -e "${BLUE}🔨 Compilando versión Release (Optimizada)...${NC}"
mkdir -p bin
go build -ldflags="-s -w" -o $BIN ./cmd/vpn
if [ $? -ne 0 ]; then exit 1; fi

echo -e "${BLUE}🌐 Configurando Namespaces de Alto Rendimiento...${NC}"
ip netns add $NS_S
ip netns add $NS_C

# Cables virtuales
ip link add v-server type veth peer name v-client
ip link set v-server netns $NS_S
ip link set v-client netns $NS_C

# Configurar interfaces físicas simuladas
# Aumentamos txqueuelen para evitar drops en el enlace virtual durante el benchmark
ip netns exec $NS_S ip addr add $PUB_IP_S/24 dev v-server
ip netns exec $NS_S ip link set v-server txqueuelen 5000 up
ip netns exec $NS_S ip link set lo up

ip netns exec $NS_C ip addr add $PUB_IP_C/24 dev v-client
ip netns exec $NS_C ip link set v-client txqueuelen 5000 up
ip netns exec $NS_C ip link set lo up

# (Eliminado sysctl problemático dentro de netns)

echo -e "${BLUE}🚀 Iniciando VPNs...${NC}"

# SERVIDOR
# Escucha en 0.0.0.0:9000. Espera cliente 10.99.0.2 (IP dinámica inicial)
ip netns exec $NS_S $BIN -mode server \
    -local "$PUB_IP_S:9000" \
    -tun tun0 \
    -key $KEY \
    -peer "$VPN_IP_C" \
    > server.log 2>&1 &
echo $! > server.pid

# CLIENTE
# FIXED: Añadido -remote para satisfacer la validación de config.go
# El routing real se hace vía -peer
ip netns exec $NS_C $BIN -mode client \
    -local "$PUB_IP_C:9000" \
    -remote "$PUB_IP_S:9000" \
    -tun tun0 \
    -key $KEY \
    -peer "$VPN_IP_S,$PUB_IP_S:9000" \
    > client.log 2>&1 &
echo $! > client.pid

sleep 2

echo -e "${BLUE}🔧 Configurando Interfaces TUN (MTU 1420)...${NC}"
ip netns exec $NS_S ip addr add $VPN_IP_S/24 dev tun0
ip netns exec $NS_S ip link set tun0 mtu 1420 up

ip netns exec $NS_C ip addr add $VPN_IP_C/24 dev tun0
ip netns exec $NS_C ip link set tun0 mtu 1420 up

# Ping de calentamiento
echo -n "   Verificando enlace... "
ip netns exec $NS_C ping -c 1 -W 1 $VPN_IP_S > /dev/null
if [ $? -eq 0 ]; then echo -e "${GREEN}OK${NC}"; else echo -e "${RED}FALLO${NC}"; cat client.log; exit 1; fi

echo -e "\n${YELLOW}🔥 EJECUTANDO BENCHMARK DE RENDIMIENTO (10 segundos)...${NC}"
echo "------------------------------------------------------------"

# Iniciar Servidor iPerf
ip netns exec $NS_S iperf3 -s -D > /dev/null

# Iniciar Cliente iPerf
# -O 2: Omitir arranque
# -P 2: 2 hilos paralelos
ip netns exec $NS_C iperf3 -c $VPN_IP_S -t 10 -O 2 -P 2

echo "------------------------------------------------------------"
