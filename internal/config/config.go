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

// Config runtime optimizada (tipos estrictos).
type Config struct {
	Mode       string
	LocalAddr  string
	TunName    string
	SecretKey  []byte
	MTU        int
	Debug      bool
	LocalVIP   net.IP
	
	// Rutas locales a inyectar en el Kernel
	Routes []string

	// Lista de peers pre-procesada para el arranque
	Peers []PeerConfig
}

// PeerConfig define la estructura para config.toml y flags.
type PeerConfig struct {
	VIP        string   `toml:"vip"`
	Endpoint   string   `toml:"endpoint"` // Opcional
	AllowedIPs []string `toml:"allowed_ips"` // <--- NUEVO: Subredes detrás del peer
}

// fileConfig es el mapeo intermedio para TOML.
type fileConfig struct {
	Interface struct {
		Mode       *string   `toml:"mode"`
		LocalAddr  *string   `toml:"local_addr"`
		TunName    *string   `toml:"tun_name"`
		PrivateKey *string   `toml:"private_key"`
		VIP        *string   `toml:"vip"`
		MTU        *int      `toml:"mtu"`
		Debug      *bool     `toml:"debug"`
		Routes     []string  `toml:"routes"`
	} `toml:"interface"`

	Peers []PeerConfig `toml:"peers"`
}

func Load() (*Config, error) {
	// 1. Definición de Flags
	configPath := flag.String("config", "config.toml", "Ruta al archivo de configuración")
	
	fMode := flag.String("mode", "", "Override: client | server")
	fLocal := flag.String("local", "", "Override: Bind Address")
	fTun := flag.String("tun", "", "Override: Interface Name")
	fKey := flag.String("key", "", "Override: Hex Private Key")
	fVIP := flag.String("vip", "", "Override: VPN IP")
	fMTU := flag.Int("mtu", 0, "Override: MTU")
	fDebug := flag.Bool("debug", false, "Override: Debug logs")
	
	fPeer := flag.String("peer", "", "Legacy: VIP,RemoteUDPAddr")

	if !flag.Parsed() {
		flag.Parse()
	}

	// 2. Valores por Defecto
	cfg := &Config{
		Mode:      "client",
		LocalAddr: "0.0.0.0:9000",
		TunName:   "tun0",
		MTU:       1420,
		Debug:     false,
	}

	// 3. Carga de Archivo
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

	// 4. Merge: File -> Config
	var fileKey, fileVIP string

	if configFileUsed {
		if fc.Interface.Mode != nil { cfg.Mode = *fc.Interface.Mode }
		if fc.Interface.LocalAddr != nil { cfg.LocalAddr = *fc.Interface.LocalAddr }
		if fc.Interface.TunName != nil { cfg.TunName = *fc.Interface.TunName }
		if fc.Interface.MTU != nil { cfg.MTU = *fc.Interface.MTU }
		if fc.Interface.Debug != nil { cfg.Debug = *fc.Interface.Debug }
		if fc.Interface.PrivateKey != nil { fileKey = *fc.Interface.PrivateKey }
		if fc.Interface.VIP != nil { fileVIP = *fc.Interface.VIP }
		if fc.Interface.Routes != nil { cfg.Routes = fc.Interface.Routes }
		
		cfg.Peers = fc.Peers
	}

	// 5. Merge: Flags -> Config (Override)
	if *fMode != "" { cfg.Mode = *fMode }
	if *fLocal != "" { cfg.LocalAddr = *fLocal }
	if *fTun != "" { cfg.TunName = *fTun }
	if *fMTU != 0 { cfg.MTU = *fMTU }
	if *fDebug { cfg.Debug = true } 

	finalKey := fileKey
	if *fKey != "" { finalKey = *fKey }

	finalVIP := fileVIP
	if *fVIP != "" { finalVIP = *fVIP }

	// 6. Validaciones
	if finalKey == "" {
		return nil, errors.New("private key es obligatoria (-key o config file)")
	}
	keyBytes, err := hex.DecodeString(finalKey)
	if err != nil {
		return nil, fmt.Errorf("formato de key invalido: %v", err)
	}
	if len(keyBytes) != 32 {
		return nil, fmt.Errorf("key debe ser 32 bytes, recibido %d", len(keyBytes))
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

	if *fPeer != "" {
		legacyPeer := parseLegacyPeer(*fPeer)
		cfg.Peers = append(cfg.Peers, legacyPeer)
	}

	return cfg, nil
}

func parseLegacyPeer(s string) PeerConfig {
	parts := strings.Split(s, ",")
	p := PeerConfig{
		VIP: parts[0],
	}
	if len(parts) > 1 {
		p.Endpoint = parts[1]
	}
	return p
}
