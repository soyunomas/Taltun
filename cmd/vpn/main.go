package main

import (
	"flag"
	"log"
	"net"
	"net/http"
	_ "net/http/pprof" // IMPORT MÁGICO
	"strings"
	
	"github.com/Soyunomas/taltun/internal/config"
	"github.com/Soyunomas/taltun/internal/engine"
)

func main() {
	peerFlag := flag.String("peer", "", "Definir peer estático: VIP,RemoteUDPAddr")
	// Flag para profiling
	pprofAddr := flag.String("pprof", "", "Habilitar pprof en address:port (ej: localhost:6060)")
	
	cfg, err := config.Load() // config.Load parsea los flags
	if err != nil {
		log.Fatalf("Error de configuración: %v", err)
	}

	// Iniciar servidor de profiling si se solicita
	if *pprofAddr != "" {
		go func() {
			log.Printf("🕵️ Profiling activo en http://%s/debug/pprof/", *pprofAddr)
			log.Println(http.ListenAndServe(*pprofAddr, nil))
		}()
	}

	// 2. Inicializar Engine
	srv, err := engine.New(cfg)
	if err != nil {
		log.Fatalf("Error creando engine: %v", err)
	}

	// 3. Registrar Peers
	if *peerFlag != "" {
		parts := strings.Split(*peerFlag, ",")
		vip := net.ParseIP(parts[0])
		if vip == nil {
			log.Fatalf("IP Virtual peer invalida: %s", parts[0])
		}
		
		remote := ""
		if len(parts) > 1 {
			remote = parts[1]
		}
		
		if err := srv.AddPeer(vip, remote); err != nil {
			log.Fatalf("Error añadiendo peer: %v", err)
		}
	} else {
		// Modo compatibilidad
		if cfg.Mode == "client" && cfg.RemoteAddr != "" {
			log.Println("⚠️ No se especificó -peer, añadiendo servidor default 10.0.0.1")
			srv.AddPeer(net.ParseIP("10.0.0.1"), cfg.RemoteAddr)
		}
		if cfg.Mode == "server" {
			log.Println("⚠️ No se especificó -peer, permitiendo cliente dinámico 10.0.0.2")
			srv.AddPeer(net.ParseIP("10.0.0.2"), "")
		}
	}

	if err := srv.Initialize(); err != nil {
		log.Fatalf("Error inicializando recursos: %v", err)
	}

	// 4. Run
	if err := srv.Run(); err != nil {
		log.Fatalf("Engine se detuvo con error: %v", err)
	}
}
