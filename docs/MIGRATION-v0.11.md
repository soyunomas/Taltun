# Migration to v0.11 / protocol v2

v0.11 is not wire-compatible with the old handshake/session format. Upgrade all nodes in a Taltun trust domain together.

## Required configuration changes

Each peer now requires a pinned X25519 public key:

    [[peers]]
    vip = "10.0.0.2"
    public_key = "<64 hex characters>"

Generate a keypair on each node with:

    ./bin/taltun-keygen

Keep the generated private key on its node. Copy only the public key into peer entries on the other participants.

## AllowedIPs changed meaning

AllowedIPs is now both routing policy and ingress source ACL. Review every peer definition before upgrading.

For a site gateway:

    allowed_ips = ["192.168.50.0/24"]

means both "route 192.168.50.0/24 to this peer" and "this peer may originate source addresses in 192.168.50.0/24".

The configured peer VIP is automatically permitted as /32.

For hub-and-spoke relay, spokes may need to authorize remote spoke/LAN prefixes on their hub peer because inner source addresses are preserved across relay.

## Lighthouse configuration

Only mark a peer as a trusted discovery authority when intended:

    lighthouse = true

Old plaintext PeerUpdate packets are not accepted. v0.11 PeerUpdate uses the authenticated v2 session and replay window.

## MTU and workers

MTU is validated to 576..2007 because the fixed packet pool is 2048 bytes and must also hold the Taltun header and AEAD tag.

UDP worker count can be pinned for testing or tuning:

    workers = 1

A value of 0 or omission uses runtime.NumCPU().

## Wire-format changes

- Handshake v2 carries static identity, ephemeral X25519 key, session ID, and authentication tag.
- A finish message confirms possession of freshly derived session material.
- Data headers include sender VIP, 64-bit session ID, and nonce.
- Header bytes are authenticated as ChaCha20-Poly1305 AAD.
- TX/RX keys, counters, and replay windows are directional/session-scoped.

Mixed v0.10/v0.11 peers will not communicate.

## Rollout procedure

1. Generate or inventory a unique X25519 keypair for every node.
2. Exchange public keys through a trusted administrative channel.
3. Update every peer entry with public_key and review AllowedIPs.
4. Configure lighthouse=true only where explicitly required.
5. Upgrade all nodes in the trust domain during the same maintenance window.
6. Run the namespace integration suite or an equivalent staging test.
7. Verify relay/subnet traffic and automatic rekey before promoting the rollout.

Rollback requires rolling the full trust domain back to the prior wire-compatible version.
