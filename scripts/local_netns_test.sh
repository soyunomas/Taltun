#!/bin/bash
# Script para simular red real en una sola máquina usando Namespaces (netns)
# Requiere root

# Crear namespaces
ip netns add ns_server
ip netns add ns_client

# Crear par de cables virtuales (veth)
ip link add v-server type veth peer name v-client

# Mover cables a namespaces
ip link set v-server netns ns_server
ip link set v-client netns ns_client

# Configurar IPs de transporte (Internet simulada)
# Servidor: 172.16.0.1
# Cliente: 172.16.0.2
ip netns exec ns_server ip addr add 172.16.0.1/24 dev v-server
ip netns exec ns_server ip link set v-server up
ip netns exec ns_server ip link set lo up

ip netns exec ns_client ip addr add 172.16.0.2/24 dev v-client
ip netns exec ns_client ip link set v-client up
ip netns exec ns_client ip link set lo up

echo "✅ Entorno de red simulado listo."
echo "   Para correr el servidor: sudo ip netns exec ns_server ./bin/vpn -mode server"
echo "   Para correr el cliente:  sudo ip netns exec ns_client ./bin/vpn -mode client"
