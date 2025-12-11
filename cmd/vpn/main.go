package main

import (
	"context"
	"flag"
	"log"
	"net"
	"net/http"
	_ "net/http/pprof"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/Soyunomas/taltun/internal/config"
	"github.com/Soyunomas/taltun/internal/engine"
)

func main() {
	pprofAddr := flag.String("pprof", "", "Habilitar pprof en address:port")

	cfg, err := config.Load()
	if err != nil {
		log.Fatalf("❌ Error de configuración: %v", err)
	}

	// 1. Setup Signal Handling (Graceful Shutdown)
	// Creamos un contexto que se cancela al recibir SIGINT (Ctrl+C) o SIGTERM
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()

	if *pprofAddr != "" {
		go func() {
			log.Printf("🕵️ Profiling activo en http://%s/debug/pprof/", *pprofAddr)
			log.Println(http.ListenAndServe(*pprofAddr, nil))
		}()
	}

	log.Printf("🔹 Iniciando Taltun (Mode: %s | VIP: %s | TUN: %s)", 
		cfg.Mode, cfg.LocalVIP, cfg.TunName)

	srv, err := engine.New(cfg)
	if err != nil {
		log.Fatalf("❌ Error creando engine: %v", err)
	}

	peersAdded := 0
	for _, p := range cfg.Peers {
		vip := net.ParseIP(p.VIP)
		if vip == nil {
			log.Printf("⚠️ Peer VIP invalida ignorada: %s", p.VIP)
			continue
		}
		
		if err := srv.AddPeer(vip, p.Endpoint); err != nil {
			log.Printf("⚠️ Error añadiendo peer %s: %v", p.VIP, err)
		} else {
			peersAdded++
		}
	}

	if peersAdded == 0 && cfg.Mode == "client" {
		log.Println("⚠️ Advertencia: Cliente iniciado sin peers configurados.")
	}

	if err := srv.Initialize(); err != nil {
		log.Fatalf("❌ Error inicializando recursos: %v", err)
	}

	// 2. Run with Context
	// Bloquea hasta que ocurra un error fatal o el usuario pulse Ctrl+C
	start := time.Now()
	if err := srv.Run(ctx); err != nil {
		log.Fatalf("❌ Engine falló: %v", err)
	}

	log.Printf("👋 Taltun detenido correctamente (Uptime: %s)", time.Since(start).Round(time.Second))
}
