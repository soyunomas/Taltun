package engine

import (
	"encoding/binary"
	"encoding/hex"
	"net"
	"testing"

	"github.com/Soyunomas/taltun/internal/config"
	tcrypto "github.com/Soyunomas/taltun/pkg/crypto"
	"github.com/Soyunomas/taltun/pkg/protocol"
)

func TestPeerUpdateRequiresTrustedLighthouseAndDoesNotDirectlyMoveTarget(t *testing.T) {
	localKey, _ := tcrypto.GenerateKeyPair()
	lighthouseKey, _ := tcrypto.GenerateKeyPair()
	targetKey, _ := tcrypto.GenerateKeyPair()

	e, err := New(&config.Config{
		Mode:      "client",
		SecretKey: localKey.Private[:],
		LocalVIP:  net.IPv4(10, 0, 0, 1),
	})
	if err != nil {
		t.Fatal(err)
	}
	defer e.Close()

	if err := e.AddPeer(
		net.IPv4(10, 0, 0, 2),
		"192.0.2.2:9000",
		hex.EncodeToString(lighthouseKey.Public[:]),
		nil,
		false,
	); err != nil {
		t.Fatal(err)
	}
	if err := e.AddPeer(
		net.IPv4(10, 0, 0, 3),
		"192.0.2.3:9000",
		hex.EncodeToString(targetKey.Public[:]),
		nil,
		false,
	); err != nil {
		t.Fatal(err)
	}

	peers := *e.peers.Load()
	source := peers[0x0a000002]
	target := peers[0x0a000003]

	var txKey, rxKey [tcrypto.KeySize]byte
	txKey[0] = 1
	rxKey[0] = 2
	eph, _ := tcrypto.GenerateKeyPair()
	source.BeginInitiatorHandshake(55, eph)
	if err := source.CompleteInitiatorHandshake(55, txKey, rxKey); err != nil {
		t.Fatal(err)
	}

	candidate := &net.UDPAddr{IP: net.IPv4(198, 51, 100, 77), Port: 51820}
	packet := makeEncryptedPeerUpdate(t, rxKey, source.VirtualIP, 55, 1, target.VirtualIP, candidate)

	// A valid encrypted control packet from an ordinary peer is not trusted.
	e.processPeerUpdatePacket(packet, source.GetEndpoint())
	if got := target.PendingInitiatorSessionID(); got != 0 {
		t.Fatalf("untrusted peer triggered handshake %d", got)
	}

	source.SetLighthouse(true)
	e.processPeerUpdatePacket(packet, source.GetEndpoint())
	if got := target.PendingInitiatorSessionID(); got == 0 {
		t.Fatal("trusted lighthouse did not trigger authenticated candidate handshake")
	}

	// Discovery never directly installs the suggested endpoint.
	if got := target.GetEndpoint(); got == nil || got.IP.Equal(candidate.IP) || got.Port == candidate.Port {
		t.Fatalf("peer update directly changed target endpoint: %v", got)
	}
}

func makeEncryptedPeerUpdate(
	t *testing.T,
	rxKey [tcrypto.KeySize]byte,
	senderVIP uint32,
	sessionID, counter uint64,
	targetVIP uint32,
	candidate *net.UDPAddr,
) []byte {
	t.Helper()
	aead, err := tcrypto.NewAEAD(rxKey)
	if err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, protocol.HeaderSize+protocol.PeerUpdatePayloadSize+aead.Overhead())
	nonce := make([]byte, protocol.NonceSize)
	binary.BigEndian.PutUint64(nonce[4:], counter)
	if _, err := protocol.EncodeControlHeader(
		buf[:protocol.HeaderSize],
		protocol.MsgTypePeerUpdate,
		senderVIP,
		sessionID,
		nonce,
	); err != nil {
		t.Fatal(err)
	}
	payload := make([]byte, protocol.PeerUpdatePayloadSize)
	if _, err := protocol.EncodePeerUpdatePayload(payload, targetVIP, candidate); err != nil {
		t.Fatal(err)
	}
	sealed := aead.Seal(
		buf[protocol.HeaderSize:protocol.HeaderSize],
		nonce,
		payload,
		buf[:protocol.HeaderSize],
	)
	return buf[:protocol.HeaderSize+len(sealed)]
}
