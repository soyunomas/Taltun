# Taltun v0.11.0-rc1 — Security Hardening

This release candidate is a protocol-breaking security and reliability release. It is intended for staging and controlled validation before a production-ready declaration.

## Security changes

- Pinned X25519 public identity is mandatory for every peer.
- Deprecated Curve25519 ScalarMult use was replaced with X25519 validation, including rejection of low-order public keys.
- Handshake v2 uses fresh ephemeral X25519 material, authenticated transcripts, a random 64-bit session ID, and an explicit finish confirmation.
- HKDF-SHA256 derives independent traffic keys for each direction.
- ChaCha20-Poly1305 authenticates the Taltun data/control header as AAD.
- TX counters and replay windows are scoped to a session generation; counter wrap is rejected.
- Rekey now creates fresh cryptographic traffic keys. The previous generation is retained for a 30-second transition window.
- AllowedIPs is enforced as an inbound source ACL in addition to outbound route selection.
- Lighthouse PeerUpdate messages are encrypted, replay-protected, accepted only from locally trusted Lighthouse peers, and cannot directly install another peer's endpoint.

## Routing and concurrency

- IPv4 longest-prefix matching is now exact for arbitrary prefix lengths.
- Dynamic route changes use immutable path copy-on-write and atomic root publication.
- Activity timestamps and Lighthouse notification throttling are atomic.
- Shutdown is idempotent and waits for engine workers; cookie rotation is stoppable.
- Initial/rekey handshakes are retransmitted after a bounded timeout so a lost UDP handshake cannot strand a peer indefinitely.

## Verification

CI now runs:

- go vet
- unit tests
- race detector
- parser fuzzing
- full build
- privileged Linux namespace integration

The namespace suite validates client/server connectivity, client-to-client relay, subnet routing, process restart recovery, and automatic two-minute rekey.

## Performance reference

GitHub Actions Performance run 36919598224 on a 4-vCPU Azure runner measured:

- 1 worker: ~0.889 Gbit/s TCP, ~27.7% UDP loss at a 1 Gbit/s offered load, 0.308 ms average ping.
- 4 workers: ~1.126 Gbit/s TCP, ~9.0% UDP loss at a 1 Gbit/s offered load, 0.248 ms average ping.
- Header parsing/encoding: 0 allocs/op in microbenchmarks.
- Session seal/open paths: 1 alloc/op in the measured microbenchmarks.

These are environment-specific measurements, not universal throughput guarantees. See docs/PERFORMANCE.md.

## Breaking changes

v0.11 is not wire-compatible with the previous handshake/session format. Upgrade a trust domain together.

Every peer must now have public_key configured. Review AllowedIPs because it now also authorizes inbound source prefixes. Lighthouse trust is explicit with lighthouse = true.

See docs/MIGRATION-v0.11.md before upgrading.

## Known limitations

- IPv4 only.
- Not post-quantum secure.
- Project-specific protocol; no external professional cryptographic audit has been completed.
- The current fixed-buffer architecture constrains MTU to 576..2007.
- Performance varies by CPU, kernel, NIC, topology, and workload.

This prerelease should be treated as a validation candidate, not a production-readiness declaration.
