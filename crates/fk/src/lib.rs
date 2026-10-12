//! fk — Fake Kernel test double harness.
//!
//! Provides deterministic syscall simulation, mock kernel interfaces, and
//! Landlock/seccomp test doubles for sandboxing and container lifecycle testing.
//!
//! # Architecture
//! Anchored in the systems principles of **Bryan Cantrill & Graydon Hoare**.
//! Separates zero-I/O mock kernel domain logic (`fk-domain`) from systems runtime helpers.

pub use fk_domain::*;

/// A high-level runtime handle for simulated kernel execution.
#[derive(Debug, Default)]
pub struct MockKernel {
    state: MockKernelState,
}

impl MockKernel {
    /// Creates a new mock kernel instance.
    pub fn new() -> Self {
        Self {
            state: MockKernelState::default(),
        }
    }

    /// Accesses the underlying simulated kernel state.
    pub fn state(&self) -> &MockKernelState {
        &self.state
    }

    /// Mutably accesses the underlying simulated kernel state.
    pub fn state_mut(&mut self) -> &mut MockKernelState {
        &mut self.state
    }

    /// Executes a syscall against the mock kernel.
    pub fn execute(&mut self, syscall: &Syscall) -> SyscallResult {
        self.state.dispatch(syscall)
    }
}

/// Initializes the `fk` test double engine.
pub fn init() -> anyhow::Result<()> {
    tracing::debug!("Initialized fk mock kernel harness");
    Ok(())
}
