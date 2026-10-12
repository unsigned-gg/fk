//! fk (Fake Kernel CLI)
use anyhow::Result;
use fk::{MockKernel, MockLandlockRule, Syscall, SyscallResult};

fn main() -> Result<()> {
    println!("fk v0.1.0 - Fake Kernel Test Double Harness");
    println!("Deterministic syscall simulation & Landlock/seccomp test doubles for kl & sbx.");

    let mut kernel = MockKernel::new();
    println!("Simulated kernel initialized with PID 1.");

    // Exercise simulated Landlock restriction
    println!("Applying simulated Landlock restriction to /workspace...");
    let res = kernel.execute(&Syscall::LandlockRestrictSelf {
        rules: vec![MockLandlockRule {
            path: "/workspace".into(),
            allowed_access: 0xFF,
        }],
    });
    assert_eq!(res, SyscallResult::Ok(0));
    println!("Landlock confinement active: OK.");

    Ok(())
}
