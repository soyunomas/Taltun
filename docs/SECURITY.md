# Security model

Taltun v0.11 uses pinned static X25519 identities plus fresh ephemeral X25519 material for every session.

## Peer identity

Every peer entry must contain the peer VIP and its X25519 public key. A claimed VIP is not an identity by itself. The v2 handshake verifies the configured static public key and requires proof of possession of the corresponding private key.

Generate identities with:

    go run ./cmd/keygen

Keep private keys local to the node. Distribute only public keys through an authenticated administrative channel.

## Session establishment and rekey

The v2 handshake is a three-message exchange: init, response, finish. Each session has fresh ephemeral X25519 keys and a random 64-bit session identifier. HKDF-SHA256 derives separate initiator-to-responder, responder-to-initiator, and finish keys.

Traffic is protected with ChaCha20-Poly1305. Data and authenticated control headers are included as AEAD additional authenticated data.

Automatic rekey occurs after two minutes. The previous traffic generation remains available for 30 seconds to tolerate packets already in flight. Each generation owns its own TX counter and replay window.

## AllowedIPs

AllowedIPs has two security-relevant meanings:

1. Outbound route selection: traffic to an AllowedIPs prefix is sent to that peer.
2. Inbound source authorization: authenticated traffic from that peer may only claim source addresses inside its AllowedIPs prefixes.

A peer's own VIP is always authorized as a /32 even when AllowedIPs is empty.

In a relay topology, the receiving spoke must authorize the prefixes that may legitimately arrive through its hub because relayed packets are re-encrypted by the hub session while retaining the original inner source address.

## Lighthouse trust

A peer is trusted as a Lighthouse only when its local peer entry contains:

    lighthouse = true

PeerUpdate messages are encrypted and authenticated inside an established v2 session and consume that session's replay counter/window. An update is only an endpoint candidate. Taltun does not install the advertised endpoint for the target peer until that target completes a fresh authenticated v2 handshake from the candidate address.

## Endpoint migration

Authenticated data may update the source endpoint associated with the peer that successfully decrypted the packet. Lighthouse discovery cannot directly migrate another peer's trusted endpoint.

## DoS cookies

Cookie replies are stateless anti-DoS challenges. They are not trusted state-changing control messages. Their purpose is to prove return-routability of the source IP before expensive handshake processing under load.

## Current limitations

- IPv4 only.
- X25519 is not post-quantum secure.
- The protocol is project-specific and has not received an external professional cryptographic audit.
- A compromised static private key enables impersonation of that peer for future sessions.
- Forward secrecy for past traffic depends on ephemeral private material no longer being available.
- Endpoint and route configuration remains trusted local administration.
- Performance tuning is platform-dependent; see docs/PERFORMANCE.md.

## Security reports

When reporting a suspected security issue, include the affected commit, configuration, reproduction steps, and whether a valid peer identity is required.
