# Performance validation

This document records reproducible measurements for Taltun. Results are environment-specific and are not universal throughput guarantees.

## Reference run

- GitHub Actions workflow: Performance
- Run: 36919598224
- Commit: 513dfba3dbb0f1371ad88c2f2bec175e734ceb05
- Runner: Azure-hosted GitHub Actions, 4 vCPU
- Kernel: 6.17.0-1022-azure
- Transport: Linux network namespaces connected with veth
- Tunnel MTU: 1380
- TCP: iperf3, 10 seconds, 4 parallel streams
- UDP: iperf3, 5 seconds, 1 Gbit/s target
- Latency: 20 ICMP samples
- CPU profile: 5-second Go pprof sample during TCP load

## End-to-end results

| Metric | 1 UDP worker | 4 UDP workers |
| --- | ---: | ---: |
| TCP throughput | 0.889 Gbit/s | 1.126 Gbit/s |
| UDP offered/observed rate | 0.9998 Gbit/s | 0.9998 Gbit/s |
| UDP loss | 27.68% | 9.02% |
| UDP packets over 5 s | 470,577 | 470,554 |
| Approx. packet rate | 94.1 kpps | 94.1 kpps |
| Average ping RTT | 0.308 ms | 0.248 ms |

On this runner, increasing the UDP worker count from 1 to 4 improved TCP throughput by about 26.7% and substantially reduced UDP loss at a 1 Gbit/s offered load. This supports the usefulness of SO_REUSEPORT sharding in this environment, but it is not evidence that scaling is linear or portable to other CPUs, kernels, NICs, or workloads.

## CPU profile

The 4-worker profile attributed roughly 69.7% of flat CPU samples to runtime/syscall activity and about 8.4% to ChaCha20-Poly1305 open. The 1-worker profile showed the same pattern: roughly 66.0% syscall activity and 6.8% ChaCha20-Poly1305 open.

The result indicates that this benchmark is primarily I/O/syscall constrained rather than purely cryptography constrained. The single TUN reader remains a serial stage, but these measurements do not establish it as the sole throughput bottleneck. Future optimization work should profile before changing that architecture.

## Microbenchmarks

The same workflow produced:

- Parse data header: 2.199 ns/op, 0 B/op, 0 allocs/op.
- Encode data header: 0.2732 ns/op, 0 B/op, 0 allocs/op.
- Session seal path: 684.2 ns/op, 2017 MB/s, 16 B/op, 1 alloc/op.
- Session open + replay path: 1398 ns/op, 987 MB/s, 16 B/op, 1 alloc/op.

Therefore Taltun must not claim that the complete dataplane is zero-allocation. The packet header parser/encoder is zero-allocation in this microbenchmark; the measured session crypto paths are not.

## Reproducing

Run the local benchmark as root on Linux:

    sudo env PATH="$PATH" WORKERS=1 BENCH_OUT="$PWD/benchmark-results-1" ./scripts/bench_throughput.sh
    sudo env PATH="$PATH" WORKERS=0 BENCH_OUT="$PWD/benchmark-results-auto" ./scripts/bench_throughput.sh

Or run the GitHub Actions Performance workflow. Each matrix job uploads benchmark.json, raw iperf JSON, ping output, logs, and cpu.prof.

Do not compare results across machines without recording CPU, kernel, worker count, MTU, and test duration.
