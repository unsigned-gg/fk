# fk

> fk (Terminal Overdrive Trace Corpus Generator)  
> Terminal Overdrive: generates trace corpus for complex Rust implementations by agents. Experiments with agentic swarm orchestration in SDLC contexts.  
> Dual-licensed under `Apache-2.0 OR MIT`.

## Philosophical Foundations
- **Champion Inspiration:** Alex Crichton & Graydon Hoare
- **Zero Days Open Source Initiative (ZOSI):** Machine sympathy, low-level efficiency, and verified contracts.
- **Architecture:** Zero-I/O domain model in `fk-domain` separated from systems runtime in `fk`.

## Crates
- `crates/fk`: Systems implementation and runtime interfaces.
- `crates/fk-domain`: Pure zero-I/O domain models, validation, and algebraic state machines.

## Building
All builds must specify `-j 2` to prevent memory exhaustion on shared multi-agent hosts:
```bash
cargo build -j 2
cargo test -j 2
```
