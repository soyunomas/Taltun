package netutil

import (
	"fmt"
	"net"

	"github.com/vishvananda/netlink"
)

// ConfigureInterface asigna IP, MTU y levanta la interfaz.
func ConfigureInterface(ifaceName string, ip net.IP, mtu int) error {
	link, err := netlink.LinkByName(ifaceName)
	if err != nil {
		return fmt.Errorf("no se encontró interfaz %s: %v", ifaceName, err)
	}

	if err := netlink.LinkSetMTU(link, mtu); err != nil {
		return fmt.Errorf("error setting MTU %d: %v", mtu, err)
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

	if err := netlink.LinkSetUp(link); err != nil {
		return fmt.Errorf("error levantando interfaz: %v", err)
	}

	return nil
}

// AddRoutes inyecta rutas estáticas en el Kernel apuntando a la interfaz.
// routes: lista de CIDRs (ej: "192.168.0.0/16").
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
