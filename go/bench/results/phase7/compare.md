# TREMOR vs Vector vs Fluent Bit (20261026-150240)
- CPU: Apple M2 (8 cores: 4 performance + 4 efficiency)
- RAM: 8 GiB
- OS: macOS 26.3
- Go: go1.26.3
- tremor GOMAXPROCS=4, loadgen GOMAXPROCS=4 (same machine)
- vector: vector 0.59.0 (aarch64-apple-darwin a3231c7 2026-10-06 13:52:51.733983360)
- fluent-bit: Fluent Bit v5.1.5
- offered 600000 ev/s for 30s, batch 100, 10 services, 3 runs per tool
fluent-bit       mean accepted    60570 ev/s, peak RSS 54 MB
tremor           mean accepted   236442 ev/s, peak RSS 184 MB
tremor-noredact  mean accepted   296778 ev/s, peak RSS 188 MB
vector           mean accepted    62407 ev/s, peak RSS 211 MB
