package config

import (
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"net"
)

type Config struct {
	Mode       string 
	LocalAddr  string
	RemoteAddr string 
	TunName    string
	SecretKey  []byte
	MTU        int
	Debug      bool
	
	// NUEVO: Identidad propia
	LocalVIP   net.IP 
}

func Load() (*Config, error) {
	mode := flag.String("mode", "client", "Modo: client | server")
	local := flag.String("local", "0.0.0.0:9000", "Bind Address")
	remote := flag.String("remote", "", "Legacy Remote")
	tun := flag.String("tun", "tun0", "Interface Name")
	keyHex := flag.String("key", "", "Hex Private Key (32 bytes)")
	vipStr := flag.String("vip", "", "Mi IP Virtual VPN (ej: 10.0.0.2)") // <--- NUEVO
	mtu := flag.Int("mtu", 1420, "MTU")
	debug := flag.Bool("debug", false, "Debug logs")

	if !flag.Parsed() {
		flag.Parse()
	}

	if *keyHex == "" {
		return nil, errors.New("-key es obligatoria")
	}

	key, err := hex.DecodeString(*keyHex)
	if err != nil {
		return nil, fmt.Errorf("bad key: %v", err)
	}
	if len(key) != 32 {
		return nil, fmt.Errorf("key len must be 32, got %d", len(key))
	}

	if _, err := net.ResolveUDPAddr("udp", *local); err != nil {
		return nil, fmt.Errorf("bad local addr: %v", err)
	}
	
	// Validar VIP
	var vip net.IP
	if *vipStr != "" {
		vip = net.ParseIP(*vipStr)
		if vip == nil {
			return nil, fmt.Errorf("bad vip: %s", *vipStr)
		}
		vip = vip.To4()
	} else {
		// En versiones futuras podríamos inferirlo, pero por ahora es obligatorio
		// para que el handshake funcione bien.
		return nil, errors.New("-vip es obligatorio para el handshake")
	}

	return &Config{
		Mode:       *mode,
		LocalAddr:  *local,
		RemoteAddr: *remote,
		TunName:    *tun,
		SecretKey:  key,
		MTU:        *mtu,
		Debug:      *debug,
		LocalVIP:   vip,
	}, nil
}
