# Taltun — Security & Reliability Remediation Plan

Status: in progress  
Target branch: `main`

## Objective

Bring Taltun from a functional VPN prototype to a protocol with explicit peer identity, fresh per-session keys, nonce separation between directions, replay state scoped to a session, authenticated control-plane messages, deterministic integration tests, and CI-enforced correctness.

## Phase 0 — Safety baseline

- [x] Audit current `main`, `dev`, and `Faro` implementations.
- [x] Identify critical protocol/security defects.
- [ ] Add regression tests for each critical issue before/with the corresponding fix.
- [ ] Add CI for build, unit tests, race tests, vet, and Linux integration tests.

Acceptance:
- Every critical finding has a regression test or an explicit integration test.
- `main` is always buildable by CI.

## Phase 1 — Peer identity and handshake foundations

- [ ] Add `public_key` to peer configuration.
- [ ] Reject peers without a valid pinned X25519 public key.
- [ ] Replace deprecated `curve25519.ScalarMult` with `curve25519.X25519`.
- [ ] Reject low-order/invalid X25519 peer public keys.
- [ ] Bind the handshake to the configured peer identity instead of trusting the claimed VIP.
- [ ] Add handshake transcript material suitable for deterministic key derivation.

Acceptance:
- A peer presenting a public key different from the pinned key cannot establish a session.
- Low-order X25519 inputs are rejected.
- A claimed VIP alone is insufficient to impersonate a peer.

## Phase 2 — Fresh sessions, directional keys, nonces

- [ ] Introduce fresh ephemeral X25519 material per handshake/session.
- [ ] Derive independent TX and RX keys from an authenticated transcript.
- [ ] Include both peer identities and session-specific entropy in the KDF.
- [ ] Define a session identifier / generation.
- [ ] Scope TX counters to a session.
- [ ] Ensure a `(key, nonce)` pair can never repeat across direction, rekey, or restart.
- [ ] Replace the current nominal rekey with real cryptographic rekeying.

Acceptance:
- Both directions use different traffic keys.
- Reconnecting/restarting creates different traffic keys.
- Rekey changes traffic keys.
- Nonce counters may restart only when the key also changes.

## Phase 3 — Replay and key lifecycle

- [ ] Scope replay windows to a specific session/key generation.
- [ ] Keep separate replay state for current and previous keys during graceful rollover.
- [ ] Reset/drop obsolete replay state when the previous key expires.
- [ ] Add restart and rollover replay regression tests.

Acceptance:
- Legitimate packets from a fresh session are accepted even when their counters restart.
- Replays from the same session are rejected.
- Replays from an expired session cannot be accepted through rollover state.

## Phase 4 — Routing and authorization

- [ ] Separate route selection from ingress authorization.
- [ ] Enforce source/ingress policy per authenticated peer.
- [ ] Define exact `AllowedIPs` semantics and test spoofing cases.
- [ ] Preserve exact IPv4 LPM semantics for arbitrary CIDR lengths.
- [ ] Reject IPv6 configuration explicitly until the dataplane supports it.

Acceptance:
- A peer cannot inject source addresses/prefixes it is not authorized to originate.
- Arbitrary IPv4 CIDRs such as /22, /23, /31, and /32 route exactly.

## Phase 5 — Lighthouse/control-plane security

- [ ] Authenticate all control-plane messages.
- [ ] Never accept unauthenticated `PeerUpdate` endpoint changes.
- [ ] Bind endpoint discovery/hole punching to an authenticated lighthouse session.
- [ ] Add replay protection to control-plane messages.
- [ ] Review endpoint migration rules and rate limits.

Acceptance:
- Forged UDP control packets cannot change a peer endpoint or trigger trusted state changes.

## Phase 6 — Concurrency and lifecycle

- [ ] Remove data races on timestamps/state.
- [ ] Make dynamic router updates genuinely copy-on-write or consistently synchronized.
- [ ] Make shutdown deterministic and idempotent.
- [ ] Ensure goroutines and channels terminate cleanly.
- [ ] Run the engine under `-race` in CI.

Acceptance:
- Race detector passes representative peer traffic, rekey, endpoint migration, and shutdown tests.

## Phase 7 — Integration tests and CI

- [ ] Fix `scripts/run_integration_test.sh` so it does not re-add addresses already configured by Taltun.
- [ ] Build a two-namespace client/server integration test.
- [ ] Add restart/rekey tests.
- [ ] Add client-to-client relay and subnet-routing tests.
- [ ] Add GitHub Actions workflow for supported Go/Linux versions.
- [ ] Add fuzz targets for packet parsers.

Acceptance:
- Clean checkout -> CI -> build/test/race/integration passes without manual intervention.

## Phase 8 — Performance validation

Only after protocol correctness is established:

- [ ] Benchmark complete TUN -> encrypt -> UDP and UDP -> decrypt -> TUN paths.
- [ ] Measure allocations/op, packets/s, throughput, CPU/core scaling, latency, drops.
- [ ] Profile with pprof/perf before changing concurrency.
- [ ] Validate SO_REUSEPORT scaling.
- [ ] Validate whether a single TUN TX goroutine limits throughput.
- [ ] Keep routing optimizations only when semantics remain exact.
- [ ] Add reproducible benchmark methodology.

Acceptance:
- Performance claims in README are backed by reproducible commands and captured results.

## Phase 9 — Documentation and release hardening

- [ ] Align README Go requirement with `go.mod`.
- [ ] Remove or qualify unsupported claims: PFS, kernel bypass, zero-copy, zero-allocation, AES/AVX.
- [ ] Document trust model, identity provisioning, key rotation, AllowedIPs semantics, and limitations.
- [ ] Add upgrade/migration notes if config format changes.
- [ ] Cut a security-focused prerelease before declaring production readiness.

## Immediate implementation order

1. Pinned peer public keys.
2. Safe X25519 validation.
3. Authenticated handshake identity checks.
4. Fresh ephemeral handshake and transcript KDF.
5. Directional session keys.
6. Session-scoped nonces and replay windows.
7. Regression tests.
8. Integration/CI.
9. Routing/control-plane hardening.
10. Performance work.

## Non-goals during the security pass

- No new performance claims.
- No new P2P/Lighthouse features until control-plane authentication exists.
- No micro-optimizations that complicate protocol correctness.
- No production-ready label until the security acceptance criteria above pass.
