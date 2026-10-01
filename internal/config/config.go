package config

import (
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"net"
	"os"
	"strings"

	"github.com/pelletier/go-toml/v2"
)

const keySize = 32

// Config runtime optimizada (tipos estrictos).
type Config struct {
	Mode      string
	LocalAddr string
	TunName   string
	SecretKey []byte
	MTU       int
	Debug     bool
	LocalVIP  net.IP

	// Rutas locales a inyectar en el Kernel.
	Routes []string

	// Lista de peers pre-procesada para el arranque.
	Peers []PeerConfig
}

// PeerConfig define la estructura para config.toml y flags.
type PeerConfig struct {
	VIP        string   `toml:"vip"`
	PublicKey  string   `toml:"public_key"`
	Endpoint   string   `toml:"endpoint"` // Opcional
	AllowedIPs []string `toml:"allowed_ips"`
}

// fileConfig es el mapeo intermedio para TOML.
type fileConfig struct {
	Interface struct {
		Mode       *string  `toml:"mode"`
		LocalAddr  *string  `toml:"local_addr"`
		TunName    *string  `toml:"tun_name"`
		PrivateKey *string  `toml:"private_key"`
		VIP        *string  `toml:"vip"`
		MTU        *int     `toml:"mtu"`
		Debug      *bool    `toml:"debug"`
		Routes     []string `toml:"routes"`
	} `toml:"interface"`

	Peers []PeerConfig `toml:"peers"`
}

func Load() (*Config, error) {
	configPath := flag.String("config", "config.toml", "Ruta al archivo de configuración")

	fMode := flag.String("mode", "", "Override: client | server")
	fLocal := flag.String("local", "", "Override: Bind Address")
	fTun := flag.String("tun", "", "Override: Interface Name")
	fKey := flag.String("key", "", "Override: Hex Private Key")
	fVIP := flag.String("vip", "", "Override: VPN IP")
	fMTU := flag.Int("mtu", 0, "Override: MTU")
	fDebug := flag.Bool("debug", false, "Override: Debug logs")

	fPeer := flag.String("peer", "", "Legacy: VIP,RemoteUDPAddr,PeerPublicKeyHex")

	if !flag.Parsed() {
		flag.Parse()
	}

	cfg := &Config{
		Mode:      "client",
		LocalAddr: "0.0.0.0:9000",
		TunName:   "tun0",
		MTU:       1420,
		Debug:     false,
	}

	var fc fileConfig
	configFileUsed := false

	if _, err := os.Stat(*configPath); err == nil {
		data, err := os.ReadFile(*configPath)
		if err != nil {
			return nil, fmt.Errorf("error leyendo config file: %v", err)
		}
		if err := toml.Unmarshal(data, &fc); err != nil {
			return nil, fmt.Errorf("error parseando TOML: %v", err)
		}
		configFileUsed = true
	} else if *configPath != "config.toml" {
		return nil, fmt.Errorf("archivo config no encontrado: %s", *configPath)
	}

	var fileKey, fileVIP string

	if configFileUsed {
		if fc.Interface.Mode != nil {
			cfg.Mode = *fc.Interface.Mode
		}
		if fc.Interface.LocalAddr != nil {
			cfg.LocalAddr = *fc.Interface.LocalAddr
		}
		if fc.Interface.TunName != nil {
			cfg.TunName = *fc.Interface.TunName
		}
		if fc.Interface.MTU != nil {
			cfg.MTU = *fc.Interface.MTU
		}
		if fc.Interface.Debug != nil {
			cfg.Debug = *fc.Interface.Debug
		}
		if fc.Interface.PrivateKey != nil {
			fileKey = *fc.Interface.PrivateKey
		}
		if fc.Interface.VIP != nil {
			fileVIP = *fc.Interface.VIP
		}
		if fc.Interface.Routes != nil {
			cfg.Routes = fc.Interface.Routes
		}

		cfg.Peers = fc.Peers
	}

	if *fMode != "" {
		cfg.Mode = *fMode
	}
	if *fLocal != "" {
		cfg.LocalAddr = *fLocal
	}
	if *fTun != "" {
		cfg.TunName = *fTun
	}
	if *fMTU != 0 {
		cfg.MTU = *fMTU
	}
	if *fDebug {
		cfg.Debug = true
	}

	finalKey := fileKey
	if *fKey != "" {
		finalKey = *fKey
	}

	finalVIP := fileVIP
	if *fVIP != "" {
		finalVIP = *fVIP
	}

	if finalKey == "" {
		return nil, errors.New("private key es obligatoria (-key o config file)")
	}
	keyBytes, err := decodeKey(finalKey)
	if err != nil {
		return nil, fmt.Errorf("private key invalida: %w", err)
	}
	cfg.SecretKey = keyBytes

	if _, err := net.ResolveUDPAddr("udp", cfg.LocalAddr); err != nil {
		return nil, fmt.Errorf("local addr invalida: %v", err)
	}

	if finalVIP == "" {
		return nil, errors.New("VIP es obligatoria (-vip o config file)")
	}
	vipIP := net.ParseIP(finalVIP)
	if vipIP == nil {
		return nil, fmt.Errorf("VIP invalida: %s", finalVIP)
	}
	cfg.LocalVIP = vipIP.To4()
	if cfg.LocalVIP == nil {
		return nil, fmt.Errorf("VIP debe ser IPv4: %s", finalVIP)
	}

	if *fPeer != "" {
		cfg.Peers = append(cfg.Peers, parseLegacyPeer(*fPeer))
	}

	for i, peer := range cfg.Peers {
		if net.ParseIP(peer.VIP) == nil || net.ParseIP(peer.VIP).To4() == nil {
			return nil, fmt.Errorf("peer %d: VIP IPv4 invalida: %s", i, peer.VIP)
		}
		if peer.PublicKey == "" {
			return nil, fmt.Errorf("peer %s: public_key es obligatoria", peer.VIP)
		}
		if _, err := decodeKey(peer.PublicKey); err != nil {
			return nil, fmt.Errorf("peer %s: public_key invalida: %w", peer.VIP, err)
		}
	}

	return cfg, nil
}

func decodeKey(value string) ([]byte, error) {
	keyBytes, err := hex.DecodeString(value)
	if err != nil {
		return nil, fmt.Errorf("formato hexadecimal invalido: %w", err)
	}
	if len(keyBytes) != keySize {
		return nil, fmt.Errorf("la clave debe ser %d bytes, recibido %d", keySize, len(keyBytes))
	}
	return keyBytes, nil
}

func parseLegacyPeer(s string) PeerConfig {
	parts := strings.Split(s, ",")
	p := PeerConfig{}
	if len(parts) > 0 {
		p.VIP = strings.TrimSpace(parts[0])
	}
	if len(parts) > 1 {
		p.Endpoint = strings.TrimSpace(parts[1])
	}
	if len(parts) > 2 {
		p.PublicKey = strings.TrimSpace(parts[2])
	}
	return p
}
