package netutil

import (
	"fmt"
	"net"

	"github.com/vishvananda/netlink"
)

// AssignIP asigna la dirección IP a una interfaz ya existente.
// (tun.CreateTUN ya creó la interfaz y seteó el MTU).
func AssignIP(ifaceName string, ip net.IP) error {
	link, err := netlink.LinkByName(ifaceName)
	if err != nil {
		return fmt.Errorf("no se encontró interfaz %s: %v", ifaceName, err)
	}

	// Asegurar que está UP (wireguard-go suele levantarla, pero por seguridad)
	if err := netlink.LinkSetUp(link); err != nil {
		return fmt.Errorf("error levantando interfaz: %v", err)
	}

	ipNet := &net.IPNet{
		IP:   ip,
		Mask: net.CIDRMask(24, 32),
	}

	addr := &netlink.Addr{
		IPNet: ipNet,
		Label: "",
	}

	if err := netlink.AddrAdd(link, addr); err != nil {
		if !containsFileExists(err) {
			return fmt.Errorf("error asignando IP %s: %v", ip, err)
		}
	}

	return nil
}

// AddRoutes inyecta rutas estáticas en el Kernel apuntando a la interfaz.
func AddRoutes(ifaceName string, routes []string) error {
	if len(routes) == 0 {
		return nil
	}

	link, err := netlink.LinkByName(ifaceName)
	if err != nil {
		return err
	}
	
	linkIdx := link.Attrs().Index

	for _, cidr := range routes {
		_, dst, err := net.ParseCIDR(cidr)
		if err != nil {
			return fmt.Errorf("CIDR invalido %s: %v", cidr, err)
		}

		route := &netlink.Route{
			LinkIndex: linkIdx,
			Dst:       dst,
		}

		// ip route add <cidr> dev <ifaceName>
		if err := netlink.RouteAdd(route); err != nil {
			if !containsFileExists(err) {
				return fmt.Errorf("error añadiendo ruta %s: %v", cidr, err)
			}
		}
	}
	return nil
}

func containsFileExists(err error) bool {
	return err != nil && (err.Error() == "file exists" || 
		(len(err.Error()) > 0 && err.Error()[len(err.Error())-11:] == "file exists"))
}
