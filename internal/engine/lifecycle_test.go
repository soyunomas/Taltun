package engine

import (
	"net"
	"sync"
	"testing"

	"github.com/Soyunomas/taltun/internal/config"
	tcrypto "github.com/Soyunomas/taltun/pkg/crypto"
)

func TestCloseIsIdempotentAndStopsHandshakeWorker(t *testing.T) {
	key, err := tcrypto.GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	e, err := New(&config.Config{
		Mode:      "lighthouse",
		SecretKey: key.Private[:],
		LocalVIP:  net.IPv4(10, 0, 0, 1),
	})
	if err != nil {
		t.Fatal(err)
	}

	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		e.handshakeWorker()
	}()

	e.Close()
	e.Close()
	wg.Wait()

	select {
	case <-e.done:
	default:
		t.Fatal("engine done channel was not closed")
	}
}

func TestCloseWithoutInitializeIsSafe(t *testing.T) {
	key, _ := tcrypto.GenerateKeyPair()
	e, err := New(&config.Config{
		Mode:      "client",
		SecretKey: key.Private[:],
		LocalVIP:  net.IPv4(10, 0, 0, 1),
	})
	if err != nil {
		t.Fatal(err)
	}
	e.Close()
}
