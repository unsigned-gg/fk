//! Zero-I/O domain models for `fk` (Fake Kernel).
//!
//! Provides deterministic system call simulation, mock kernel state machines,
//! Landlock LSM rule evaluation, and seccomp-BPF test doubles.

use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};

/// Standard errno codes mapped to domain errors.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum SyscallError {
    /// EPERM / EACCES: Operation not permitted or permission denied.
    PermissionDenied,
    /// ENOENT: No such file or directory.
    NotFound,
    /// EBADF: Bad file descriptor.
    BadFileDescriptor,
    /// EINVAL: Invalid argument.
    InvalidArgument,
    /// ESRCH: No such process.
    ProcessNotFound,
    /// EEXIST: File or resource already exists.
    AlreadyExists,
}

/// Simulated syscall outcome.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum SyscallResult {
    /// Syscall completed successfully with return value.
    Ok(i64),
    /// Syscall failed with errno.
    Err(SyscallError),
}

impl SyscallResult {
    /// Returns true if the syscall succeeded.
    pub fn is_ok(&self) -> bool {
        matches!(self, SyscallResult::Ok(_))
    }

    /// Returns true if the syscall failed.
    pub fn is_err(&self) -> bool {
        matches!(self, SyscallResult::Err(_))
    }
}

/// Simulated file descriptor in the mock kernel.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MockFd {
    /// Descriptor index.
    pub fd: i32,
    /// Target path.
    pub path: String,
    /// Whether read operations are permitted.
    pub readable: bool,
    /// Whether write operations are permitted.
    pub writable: bool,
    /// Whether target is a directory.
    pub is_dir: bool,
}

/// Simulated Landlock path access rule.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MockLandlockRule {
    /// Base directory path.
    pub path: String,
    /// Permitted access bitmask.
    pub allowed_access: u64,
}

/// System calls simulated by the mock kernel.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum Syscall {
    /// openat(2) simulation.
    OpenAt {
        /// Base directory file descriptor.
        dirfd: i32,
        /// Target file path.
        path: String,
        /// Open flags.
        flags: u32,
    },
    /// read(2) simulation.
    Read {
        /// File descriptor.
        fd: i32,
        /// Requested byte count.
        count: usize,
    },
    /// write(2) simulation.
    Write {
        /// File descriptor.
        fd: i32,
        /// Byte length to write.
        len: usize,
    },
    /// close(2) simulation.
    Close {
        /// File descriptor.
        fd: i32,
    },
    /// Simulated Landlock restriction applied to the calling process.
    LandlockRestrictSelf {
        /// Path access rules.
        rules: Vec<MockLandlockRule>,
    },
    /// Simulated seccomp filter blocking specific syscall names.
    SeccompDisallow {
        /// Blocked syscall names.
        syscall_names: Vec<String>,
    },
    /// pidfd_open(2) simulation.
    PidfdOpen {
        /// Target process ID.
        pid: u32,
        /// Flags.
        flags: u32,
    },
    /// kill(2) simulation.
    Kill {
        /// Target process or process group ID.
        pid: i32,
        /// Signal number.
        sig: i32,
    },
}

/// Represents an isolated mock process within the simulated kernel state.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MockProcess {
    /// Process ID.
    pub pid: u32,
    /// Process group ID.
    pub pgid: u32,
    /// Table of open file descriptors.
    pub fds: HashMap<i32, MockFd>,
    /// Next available file descriptor index.
    pub next_fd: i32,
    /// Whether Landlock restriction is active.
    pub landlock_active: bool,
    /// Active Landlock access rules.
    pub landlock_rules: Vec<MockLandlockRule>,
    /// Blocked syscall names from seccomp.
    pub seccomp_blocked: HashSet<String>,
}

impl MockProcess {
    /// Creates a new mock process with standard streams initialized.
    pub fn new(pid: u32, pgid: u32) -> Self {
        let mut fds = HashMap::new();
        fds.insert(0, MockFd { fd: 0, path: "/dev/stdin".into(), readable: true, writable: false, is_dir: false });
        fds.insert(1, MockFd { fd: 1, path: "/dev/stdout".into(), readable: false, writable: true, is_dir: false });
        fds.insert(2, MockFd { fd: 2, path: "/dev/stderr".into(), readable: false, writable: true, is_dir: false });

        Self {
            pid,
            pgid,
            fds,
            next_fd: 3,
            landlock_active: false,
            landlock_rules: Vec::new(),
            seccomp_blocked: HashSet::new(),
        }
    }
}

/// Deterministic in-memory kernel state machine.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MockKernelState {
    /// Active simulated processes.
    pub processes: HashMap<u32, MockProcess>,
    /// Currently executing process ID.
    pub current_pid: u32,
    /// Known simulated filesystem paths.
    pub known_filesystem_paths: HashSet<String>,
}

impl Default for MockKernelState {
    fn default() -> Self {
        let mut processes = HashMap::new();
        processes.insert(1, MockProcess::new(1, 1));

        let mut known_filesystem_paths = HashSet::new();
        known_filesystem_paths.insert("/".into());
        known_filesystem_paths.insert("/etc".into());
        known_filesystem_paths.insert("/tmp".into());
        known_filesystem_paths.insert("/workspace".into());

        Self {
            processes,
            current_pid: 1,
            known_filesystem_paths,
        }
    }
}

impl MockKernelState {
    /// Registers a known path in the simulated filesystem.
    pub fn add_path(&mut self, path: impl Into<String>) {
        self.known_filesystem_paths.insert(path.into());
    }

    /// Dispatches a syscall against the current active process.
    pub fn dispatch(&mut self, syscall: &Syscall) -> SyscallResult {
        // Pre-check operations that reference other processes
        match syscall {
            Syscall::PidfdOpen { pid: target_pid, .. } => {
                if !self.processes.contains_key(target_pid) {
                    return SyscallResult::Err(SyscallError::ProcessNotFound);
                }
            }
            Syscall::Kill { pid: target_pid, .. } => {
                if *target_pid > 0 && !self.processes.contains_key(&(*target_pid as u32)) {
                    return SyscallResult::Err(SyscallError::ProcessNotFound);
                }
            }
            _ => {}
        }

        let pid = self.current_pid;
        let proc = match self.processes.get_mut(&pid) {
            Some(p) => p,
            None => return SyscallResult::Err(SyscallError::ProcessNotFound),
        };

        // 1. Evaluate seccomp blocks
        let call_name = match syscall {
            Syscall::OpenAt { .. } => "openat",
            Syscall::Read { .. } => "read",
            Syscall::Write { .. } => "write",
            Syscall::Close { .. } => "close",
            Syscall::LandlockRestrictSelf { .. } => "landlock_restrict_self",
            Syscall::SeccompDisallow { .. } => "seccomp",
            Syscall::PidfdOpen { .. } => "pidfd_open",
            Syscall::Kill { .. } => "kill",
        };

        if proc.seccomp_blocked.contains(call_name) {
            return SyscallResult::Err(SyscallError::PermissionDenied);
        }

        // 2. Execute simulated operation
        match syscall {
            Syscall::OpenAt { path, .. } => {
                // Landlock check
                if proc.landlock_active {
                    let mut allowed = false;
                    for rule in &proc.landlock_rules {
                        if path.starts_with(&rule.path) {
                            allowed = true;
                            break;
                        }
                    }
                    if !allowed {
                        return SyscallResult::Err(SyscallError::PermissionDenied);
                    }
                }

                if !self.known_filesystem_paths.contains(path) && !path.starts_with("/tmp") {
                    return SyscallResult::Err(SyscallError::NotFound);
                }

                let fd = proc.next_fd;
                proc.next_fd += 1;
                proc.fds.insert(fd, MockFd {
                    fd,
                    path: path.clone(),
                    readable: true,
                    writable: true,
                    is_dir: false,
                });

                SyscallResult::Ok(fd as i64)
            }
            Syscall::Read { fd, count } => {
                match proc.fds.get(fd) {
                    Some(f) if f.readable => SyscallResult::Ok(*count as i64),
                    Some(_) => SyscallResult::Err(SyscallError::PermissionDenied),
                    None => SyscallResult::Err(SyscallError::BadFileDescriptor),
                }
            }
            Syscall::Write { fd, len } => {
                match proc.fds.get(fd) {
                    Some(f) if f.writable => SyscallResult::Ok(*len as i64),
                    Some(_) => SyscallResult::Err(SyscallError::PermissionDenied),
                    None => SyscallResult::Err(SyscallError::BadFileDescriptor),
                }
            }
            Syscall::Close { fd } => {
                if proc.fds.remove(fd).is_some() {
                    SyscallResult::Ok(0)
                } else {
                    SyscallResult::Err(SyscallError::BadFileDescriptor)
                }
            }
            Syscall::LandlockRestrictSelf { rules } => {
                proc.landlock_active = true;
                proc.landlock_rules = rules.clone();
                SyscallResult::Ok(0)
            }
            Syscall::SeccompDisallow { syscall_names } => {
                for name in syscall_names {
                    proc.seccomp_blocked.insert(name.clone());
                }
                SyscallResult::Ok(0)
            }
            Syscall::PidfdOpen { pid: target_pid, .. } => {
                let fd = proc.next_fd;
                proc.next_fd += 1;
                proc.fds.insert(fd, MockFd {
                    fd,
                    path: format!("pidfd:[{target_pid}]"),
                    readable: true,
                    writable: false,
                    is_dir: false,
                });
                SyscallResult::Ok(fd as i64)
            }
            Syscall::Kill { .. } => {
                SyscallResult::Ok(0)
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_fd_lifecycle() {
        let mut kernel = MockKernelState::default();
        kernel.add_path("/workspace/file.txt");

        let open_res = kernel.dispatch(&Syscall::OpenAt {
            dirfd: -100,
            path: "/workspace/file.txt".into(),
            flags: 0,
        });
        assert!(open_res.is_ok());

        let fd = match open_res {
            SyscallResult::Ok(val) => val as i32,
            _ => unreachable!(),
        };

        // Read works
        let read_res = kernel.dispatch(&Syscall::Read { fd, count: 64 });
        assert_eq!(read_res, SyscallResult::Ok(64));

        // Close works
        let close_res = kernel.dispatch(&Syscall::Close { fd });
        assert_eq!(close_res, SyscallResult::Ok(0));

        // Read after close returns EBADF
        let bad_read = kernel.dispatch(&Syscall::Read { fd, count: 64 });
        assert_eq!(bad_read, SyscallResult::Err(SyscallError::BadFileDescriptor));
    }

    #[test]
    fn test_landlock_confinement() {
        let mut kernel = MockKernelState::default();
        kernel.add_path("/workspace/file.txt");
        kernel.add_path("/etc/shadow");

        // Restrict Landlock to /workspace only
        let restrict_res = kernel.dispatch(&Syscall::LandlockRestrictSelf {
            rules: vec![MockLandlockRule {
                path: "/workspace".into(),
                allowed_access: 0xFF,
            }],
        });
        assert_eq!(restrict_res, SyscallResult::Ok(0));

        // Opening /workspace/file.txt succeeds
        let open_allowed = kernel.dispatch(&Syscall::OpenAt {
            dirfd: -100,
            path: "/workspace/file.txt".into(),
            flags: 0,
        });
        assert!(open_allowed.is_ok());

        // Opening /etc/shadow is denied by Landlock
        let open_denied = kernel.dispatch(&Syscall::OpenAt {
            dirfd: -100,
            path: "/etc/shadow".into(),
            flags: 0,
        });
        assert_eq!(open_denied, SyscallResult::Err(SyscallError::PermissionDenied));
    }

    #[test]
    fn test_seccomp_filtering() {
        let mut kernel = MockKernelState::default();

        // Block kill syscall
        let seccomp_res = kernel.dispatch(&Syscall::SeccompDisallow {
            syscall_names: vec!["kill".into()],
        });
        assert_eq!(seccomp_res, SyscallResult::Ok(0));

        // Dispatching kill fails immediately with PermissionDenied
        let kill_res = kernel.dispatch(&Syscall::Kill { pid: 1, sig: 9 });
        assert_eq!(kill_res, SyscallResult::Err(SyscallError::PermissionDenied));
    }
}
