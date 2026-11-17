//! Exclusive ownership of logical jobs that run outside a commit.
//!
//! A long job, such as model consolidation, loads durable progress, reserves
//! work, dispatches it and saves progress again. Two runners of the same job
//! must not interleave those steps, while unrelated jobs and ordinary commits
//! keep running. A claim is an operating-system lock on one store-owned file
//! per job, so it excludes runners in any process and is released when its
//! holder drops it or dies.

/// Largest progress record a job may keep beside its claim.
pub const MAX_JOB_PROGRESS_BYTES: usize = 16 * 1_048_576;
/// [`MAX_JOB_PROGRESS_BYTES`] as a read bound, plus the one byte that shows a
/// file is longer.
const PROGRESS_READ_BOUND: u64 = 16 * 1_048_576 + 1;

/// Process-local counter that keeps one process's temporary files apart.
static TEMPORARY_COUNTER: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);

/// Exclusive ownership of one logical job, held until dropped.
///
/// The lock file is named by a digest of the job identity and holds only a
/// digest of the progress destination the job is bound to: no job content is
/// stored. A job may also keep its progress beside the claim; only the claim's
/// holder can replace it, so a stale runner cannot overwrite newer progress.
#[derive(Debug)]
pub struct JobClaim {
    _file: std::fs::File,
    progress: std::path::PathBuf,
}

impl JobClaim {
    /// The progress this job saved beside its claim, if any.
    pub fn load_progress(&self) -> crate::error::Result<Option<Vec<u8>>> {
        read_progress(&self.progress)
    }

    /// Replace the job's saved progress: written to a temporary file, flushed,
    /// renamed over the old progress, and the directory entry flushed too.
    pub fn save_progress(&self, bytes: &[u8]) -> crate::error::Result<()> {
        if bytes.len() > MAX_JOB_PROGRESS_BYTES {
            return Err(crate::error::Failure::ValueOutOfRange("job progress"));
        }
        let directory = self.progress.parent().ok_or_else(|| {
            crate::error::Failure::UnsupportedLayout("job progress has no directory".to_owned())
        })?;
        let unique = TEMPORARY_COUNTER.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let temporary = directory.join(format!(".progress.{}.{unique}.tmp", std::process::id()));
        write_synced(&temporary, bytes)?;
        if let Err(error) = std::fs::rename(&temporary, &self.progress) {
            discard(&temporary);
            return Err(crate::error::Failure::io(&self.progress, error));
        }
        std::fs::File::open(directory)
            .and_then(|handle| handle.sync_all())
            .map_err(|error| crate::error::Failure::io(directory, error))
    }
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
        lock_exclusive(&file, &path)?;
        bind_destination(&mut file, &path, &hex(&crate::payload::sha256(destination)))?;
        Ok(JobClaim {
            _file: file,
            progress: progress_path(&directory, job),
        })
    }

    /// The progress `job` saved beside its claim, read without claiming it.
    ///
    /// The holder replaces progress by rename, so this sees one complete
    /// saved state, possibly older than the holder's current one.
    pub fn job_progress(&self, job: &[u8]) -> crate::error::Result<Option<Vec<u8>>> {
        let directory = self.root().join(crate::payload::JOB_DIRECTORY);
        read_progress(&progress_path(&directory, job))
    }
}

/// Where `job` keeps its progress beside its claim.
fn progress_path(directory: &std::path::Path, job: &[u8]) -> std::path::PathBuf {
    directory.join(format!("{}.progress", hex(&crate::payload::sha256(job))))
}

/// Read one progress file, bounded; absent progress is `None`.
fn read_progress(path: &std::path::Path) -> crate::error::Result<Option<Vec<u8>>> {
    use std::io::Read as _;
    let file = match std::fs::File::open(path) {
        Ok(file) => file,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(crate::error::Failure::io(path, error)),
    };
    let mut bytes = Vec::new();
    file.take(PROGRESS_READ_BOUND)
        .read_to_end(&mut bytes)
        .map_err(|error| crate::error::Failure::io(path, error))?;
    if bytes.len() > MAX_JOB_PROGRESS_BYTES {
        return Err(crate::error::Failure::ValueOutOfRange("job progress"));
    }
    Ok(Some(bytes))
}

/// Write bytes to a new file and flush them to stable storage.
fn write_synced(path: &std::path::Path, bytes: &[u8]) -> crate::error::Result<()> {
    use std::io::Write as _;
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)
        .map_err(|error| crate::error::Failure::io(path, error))?;
    file.write_all(bytes)
        .and_then(|()| file.sync_all())
        .map_err(|error| crate::error::Failure::io(path, error))
}

/// Remove a temporary file abandoned by a failed rename. Best effort: the
/// rename error is the failure the caller sees.
#[allow(unknown_lints, ignored_result)] // best-effort cleanup after the primary failure is decided
fn discard(path: &std::path::Path) {
    let _ = std::fs::remove_file(path);
}

/// Tries to take a claim before it is reported busy.
///
/// A process that starts a child while another of its threads holds a claim
/// gives the child a copy of the lock's descriptor until the child executes
/// its program, so a claim just released can look held for that moment. A
/// runner that really holds a claim holds it far longer than these tries take.
const CLAIM_TRIES: u32 = 40;
/// The pause between two tries.
const CLAIM_RETRY: std::time::Duration = std::time::Duration::from_millis(5);

/// Take the file's exclusive lock, or report the job busy.
fn lock_exclusive(file: &std::fs::File, path: &std::path::Path) -> crate::error::Result<()> {
    for _ in 1..CLAIM_TRIES {
        match file.try_lock() {
            Ok(()) => return Ok(()),
            Err(std::fs::TryLockError::WouldBlock) => std::thread::sleep(CLAIM_RETRY),
            Err(std::fs::TryLockError::Error(error)) => {
                return Err(crate::error::Failure::io(path, error));
            }
        }
    }
    match file.try_lock() {
        Ok(()) => Ok(()),
        Err(std::fs::TryLockError::WouldBlock) => Err(crate::error::Failure::JobBusy),
        Err(std::fs::TryLockError::Error(error)) => Err(crate::error::Failure::io(path, error)),
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
