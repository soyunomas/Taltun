package netutil

import (
	"fmt"
	"net"

	"github.com/vishvananda/netlink"
)

// ConfigureInterface asigna IP, MTU y levanta la interfaz usando Netlink.
// Esto elimina la necesidad de scripts de shell externos.
// ip: La IP Virtual (se asumirá máscara /24 por defecto para compatibilidad).
func ConfigureInterface(ifaceName string, ip net.IP, mtu int) error {
	// 1. Obtener referencia al link (creado previamente por water)
	link, err := netlink.LinkByName(ifaceName)
	if err != nil {
		return fmt.Errorf("no se encontró interfaz %s: %v", ifaceName, err)
	}

	// 2. Configurar MTU
	if err := netlink.LinkSetMTU(link, mtu); err != nil {
		return fmt.Errorf("error setting MTU %d: %v", mtu, err)
	}

	// 3. Configurar IP Address
	// Asumimos /24 para permitir tráfico en la subred típica de VPN.
	// En el futuro, esto debería venir de la config.
	ipNet := &net.IPNet{
		IP:   ip,
		Mask: net.CIDRMask(24, 32),
	}

	addr := &netlink.Addr{
		IPNet: ipNet,
		Label: "",
	}

	// Intentamos añadir la dirección. Si ya existe, no fallamos fatalmente
	// (útil para reinicios rápidos).
	if err := netlink.AddrAdd(link, addr); err != nil {
		// Ignoramos error "file exists" que significa que la IP ya está puesta
		if !containsFileExists(err) {
			return fmt.Errorf("error asignando IP %s: %v", ip, err)
		}
	}

	// 4. Levantar interfaz (ip link set up)
	if err := netlink.LinkSetUp(link); err != nil {
		return fmt.Errorf("error levantando interfaz: %v", err)
	}

	return nil
}

// Helper simple para detectar error "file exists" sin depender de syscall directas
// para mantener el código portable y limpio.
func containsFileExists(err error) bool {
	return err != nil && (err.Error() == "file exists" || 
		// Checkeo más profundo si el error viene wrappeado
		(len(err.Error()) > 0 && err.Error()[len(err.Error())-11:] == "file exists"))
}
