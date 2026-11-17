//! Exclusive ownership of logical jobs that run outside a commit.
//!
//! A long job, such as model consolidation, loads durable progress, reserves
//! work, dispatches it and saves progress again. Two runners of the same job
//! must not interleave those steps, while unrelated jobs and ordinary commits
//! keep running. A claim is an operating-system lock on one store-owned file
//! per job, so it excludes runners in any process and is released when its
//! holder drops it or dies.

/// Exclusive ownership of one logical job, held until dropped.
///
/// The lock file is named by a digest of the job identity and holds only a
/// digest of the progress destination the job is bound to: no job content is
/// stored.
#[derive(Debug)]
pub struct JobClaim {
    _file: std::fs::File,
}

impl super::Workspace {
    /// Claim `job` exclusively for progress kept at `destination`.
    ///
    /// Refuses with [`crate::Failure::JobBusy`] while another runner holds the
    /// claim, and with [`crate::Failure::JobBound`] when the job was first
    /// claimed for a different destination, so choosing a second progress
    /// location cannot evade ownership.
    pub fn claim_job(&self, job: &[u8], destination: &[u8]) -> crate::error::Result<JobClaim> {
        let directory = self.root().join(crate::payload::JOB_DIRECTORY);
        std::fs::create_dir_all(&directory)
            .map_err(|error| crate::error::Failure::io(&directory, error))?;
        let path = directory.join(format!("{}.lock", hex(&crate::payload::sha256(job))));
        let mut file = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .open(&path)
            .map_err(|error| crate::error::Failure::io(&path, error))?;
        match file.try_lock() {
            Ok(()) => {}
            Err(std::fs::TryLockError::WouldBlock) => return Err(crate::error::Failure::JobBusy),
            Err(std::fs::TryLockError::Error(error)) => {
                return Err(crate::error::Failure::io(&path, error));
            }
        }
        bind_destination(&mut file, &path, &hex(&crate::payload::sha256(destination)))?;
        Ok(JobClaim { _file: file })
    }
}

/// Record `bound` in a newly created lock file, or require the one recorded.
fn bind_destination(
    file: &mut std::fs::File,
    path: &std::path::Path,
    bound: &str,
) -> crate::error::Result<()> {
    use std::io::{Read as _, Write as _};
    let mut recorded = String::with_capacity(bound.len());
    file.read_to_string(&mut recorded)
        .map_err(|error| crate::error::Failure::io(path, error))?;
    if recorded.is_empty() {
        file.write_all(bound.as_bytes())
            .map_err(|error| crate::error::Failure::io(path, error))?;
        return file
            .sync_all()
            .map_err(|error| crate::error::Failure::io(path, error));
    }
    if recorded == bound {
        Ok(())
    } else {
        Err(crate::error::Failure::JobBound)
    }
}

/// Lowercase hexadecimal of a digest.
fn hex(bytes: &[u8; 32]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut text = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        text.push(char::from(DIGITS[usize::from(byte >> 4)]));
        text.push(char::from(DIGITS[usize::from(byte & 0x0f)]));
    }
    text
}
