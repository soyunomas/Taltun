# Taltun — Security & Reliability Remediation Plan

Status: in progress  
Target branch: `main`

## Objective

Bring Taltun from a functional VPN prototype to a protocol with explicit peer identity, fresh per-session keys, nonce separation between directions, replay state scoped to a session, authenticated control-plane messages, deterministic integration tests, and CI-enforced correctness.

## Phase 0 — Safety baseline

- [x] Audit current `main`, `dev`, and `Faro` implementations.
- [x] Identify critical protocol/security defects.
- [ ] Add regression tests for each critical issue before/with the corresponding fix.
- [x] Add CI for build, unit tests, race tests, and vet.
- [ ] Add privileged Linux namespace/TUN integration tests to CI.

Acceptance:
- Every critical finding has a regression test or an explicit integration test.
- `main` is always buildable by CI.

## Phase 1 — Peer identity and handshake foundations

- [x] Add `public_key` to peer configuration.
- [x] Reject peers without a valid pinned X25519 public key.
- [x] Replace deprecated `curve25519.ScalarMult` with `curve25519.X25519`.
- [x] Reject low-order/invalid X25519 peer public keys.
- [x] Bind the handshake to the configured peer identity instead of trusting the claimed VIP.
- [x] Authenticate the static handshake transcript with a MAC derived from the pinned X25519 shared secret.
- [x] Add freshness/session material to the authenticated transcript so captured handshakes cannot be replayed into an active session.

Acceptance:
- A peer presenting a public key different from the pinned key cannot establish a session.
- Low-order X25519 inputs are rejected.
- Knowledge of the peer's public key alone is insufficient to forge a new authenticated handshake.
- Captured init/response/finish packets cannot reinstall an active session without the matching pending ephemeral state.

## Phase 2 — Fresh sessions, directional keys, nonces

- [x] Introduce fresh ephemeral X25519 material per handshake/session.
- [x] Derive independent TX and RX keys from an authenticated transcript.
- [x] Include both peer identities and session-specific entropy in the KDF.
- [x] Define a random 64-bit session identifier / generation.
- [x] Scope TX counters to a session and prevent counter wrap.
- [x] Ensure a `(key, nonce)` pair cannot repeat across direction, rekey, or restart under the implemented lifecycle.
- [x] Replace the nominal rekey with real ephemeral cryptographic rekeying.

Acceptance:
- Both directions use different traffic keys.
- Reconnecting/restarting creates different traffic keys.
- Rekey changes traffic keys.
- Nonce counters may restart only when the key also changes.

## Phase 3 — Replay and key lifecycle

- [x] Scope replay windows to a specific session/key generation.
- [x] Keep separate replay state for current and previous keys during graceful rollover.
- [x] Reset/drop obsolete replay state when the previous key expires.
- [x] Add restart/counter-reset and rollover replay regression tests.

Acceptance:
- Legitimate packets from a fresh session are accepted even when their counters restart.
- Replays from the same session are rejected.
- Replays from an expired session cannot be accepted through rollover state.

## Phase 2/3 completion notes

- Handshake v2 is a three-message authenticated exchange: init, response, finish.
- Every session uses fresh ephemeral X25519 material plus the pinned static X25519 identity.
- HKDF-SHA256 derives independent initiator→responder, responder→initiator, and finish keys.
- The data header carries a 64-bit session ID and is authenticated as ChaCha20-Poly1305 AAD.
- Each session owns its TX counter and replay window; the previous generation is accepted for a 30-second grace period only.
- Active session IDs are rejected on handshake and TX counters stop rather than wrap.
- GitHub CI passes vet, unit tests, race tests, and full build for the completed implementation.

## Phase 4 — Routing and authorization

- [x] Separate route selection from ingress authorization.
- [x] Enforce source/ingress policy per authenticated peer.
- [x] Define exact `AllowedIPs` semantics and test spoofing cases.
- [x] Preserve exact IPv4 LPM semantics for arbitrary CIDR lengths.
- [x] Reject IPv6 configuration explicitly until the dataplane supports it.

Acceptance:
- A peer cannot inject source addresses/prefixes it is not authorized to originate.
- Arbitrary IPv4 CIDRs such as /22, /23, /31, and /32 route exactly.

## Phase 5 — Lighthouse/control-plane security

- [x] Authenticate every state-changing control-plane message; cookie replies remain untrusted stateless DoS challenges.
- [x] Never accept unauthenticated `PeerUpdate` endpoint changes.
- [x] Bind endpoint discovery/hole punching to an authenticated lighthouse session.
- [x] Add replay protection to encrypted `PeerUpdate` messages by sharing the session counter/window.
- [x] Review endpoint migration rules and rate-limit Lighthouse announcements.

Acceptance:
- Forged UDP control packets cannot change a peer endpoint or trigger trusted state changes.

## Phase 6 — Concurrency and lifecycle

- [x] Remove data races on hot activity/notification timestamps.
- [x] Make dynamic router updates genuinely copy-on-write.
- [x] Make shutdown deterministic and idempotent.
- [x] Ensure engine and cookie-rotation goroutines terminate cleanly.
- [x] Run the engine and tests under `-race` in CI.

Acceptance:
- Race detector passes representative peer traffic, rekey, endpoint migration, and shutdown tests.

## Phase 4/5/6 completion notes

- `AllowedIPs` now has explicit bidirectional semantics: outbound route selection and inbound source authorization. A peer always owns its configured VIP /32 in addition to declared prefixes.
- The IPv4 router is an immutable binary trie with path copy-on-write and atomic root publication; arbitrary prefix lengths remain exact.
- `PeerUpdate` is encrypted with the existing v2 session AEAD, authenticated with the control header as AAD, and consumes the same per-session replay counter/window as data packets.
- Only peers locally configured with `lighthouse = true` may issue discovery updates.
- A Lighthouse update is only a candidate endpoint: the target endpoint is not installed until a fresh authenticated v2 handshake succeeds.
- Lighthouse notifications are rate-limited atomically.
- Hot activity timestamps are atomic; router readers are lock-free over immutable trees.
- Engine shutdown closes a shared done channel, stops cookie rotation, closes TUN/UDP resources, and waits for workers via a WaitGroup.

## Phase 7 — Integration tests and CI

- [x] Fix `scripts/run_integration_test.sh` so it does not re-add addresses already configured by Taltun.
- [x] Keep the two-namespace client/server integration test compatible with pinned peer keys.
- [ ] Add restart/rekey tests.
- [ ] Add client-to-client relay and subnet-routing tests.
- [x] Add GitHub Actions workflow for Go build, vet, unit tests, and race tests.
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

- [x] Align README Go requirement with `go.mod`.
- [ ] Remove or qualify unsupported claims: PFS, kernel bypass, zero-copy, zero-allocation, AES/AVX.
- [ ] Document trust model, identity provisioning, key rotation, AllowedIPs semantics, and limitations.
- [ ] Add upgrade/migration notes if config format changes.
- [ ] Cut a security-focused prerelease before declaring production readiness.

## Completed in first hardening increment

- [x] Added `cmd/keygen` for correct X25519 private/public provisioning.
- [x] Added regression coverage for low-order X25519 keys, pinned identities, config key parsing, and EEXIST handling.
- [x] Removed the unsafe string slicing in netlink EEXIST detection.
- [x] Corrected README claims that overstated current PFS/post-quantum/kernel-bypass/zero-copy guarantees.

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
