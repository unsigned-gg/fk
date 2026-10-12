# fk (Fake Kernel)

> **Deterministic syscall simulation, mock kernel interfaces, and Landlock/seccomp test doubles.**  
> Pure-Rust kernel test harness for [`kl`](../kl) and [`sbx`](../sbx) without requiring host root or kernel capability flags.  
> Dual-licensed under `Apache-2.0 OR MIT`.

## Architectural Role

Testing sandboxes, containment policies, and process supervisor trees usually requires Linux root permissions or specific kernel ABI capabilities. `fk` provides deterministic, zero-I/O test doubles:

1. **Deterministic Syscall State Machine:** Simulates standard POSIX/Linux syscalls (`openat`, `read`, `write`, `close`, `pidfd_open`, `kill`) in pure memory.
2. **Landlock LSM Test Double:** Evaluates path access rules, directory inheritance, and unprivileged confinement without touching host LSMs.
3. **Seccomp-BPF Syscall Filter Simulation:** Verifies that forbidden syscalls return deterministic `EPERM` / `PermissionDenied` errors.
4. **Process & FD Tracking:** Tracks mock PIDs, PGIDs, and open file descriptors to detect leaks, orphan processes, and bad FD reuse.

## Crates

| Crate | Responsibility |
| :--- | :--- |
| [`crates/fk-domain`](crates/fk-domain) | Pure zero-I/O domain types: `Syscall`, `SyscallResult`, `MockKernelState`, `MockLandlockRule`. |
| [`crates/fk`](crates/fk) | High-level `MockKernel` harness and CLI runner for testing container policies. |

## Building & Testing

All cargo invocations on multi-agent hosts MUST specify `-j 2`:

```bash
cargo build -j 2
cargo test -j 2
```
