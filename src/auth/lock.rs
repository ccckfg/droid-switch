//! Serialize credential-changing dsw commands across processes.

use std::fs::{self, File, OpenOptions};
use std::thread;
use std::time::{Duration, Instant};

use anyhow::{bail, Context, Result};

use crate::api::config;
use crate::paths::Paths;

pub struct AuthLock(File);

impl AuthLock {
    pub fn acquire(paths: &Paths) -> Result<Self> {
        fs::create_dir_all(&paths.home)?;
        let mut options = OpenOptions::new();
        options.read(true).write(true).create(true).truncate(false);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        let file = options
            .open(paths.home.join(config::AUTH_LOCK_FILE))
            .context("open credential operation lock")?;
        let deadline = Instant::now() + Duration::from_secs(config::AUTH_LOCK_TIMEOUT_SECS);
        loop {
            match fs2::FileExt::try_lock_exclusive(&file) {
                Ok(()) => return Ok(Self(file)),
                Err(e) if e.raw_os_error() == fs2::lock_contended_error().raw_os_error() => {
                    if Instant::now() >= deadline {
                        bail!(
                            "another dsw command is updating credentials; retry after it finishes"
                        );
                    }
                    thread::sleep(Duration::from_millis(config::AUTH_LOCK_POLL_MS));
                }
                Err(e) => return Err(e).context("lock credential operations"),
            }
        }
    }
}

impl Drop for AuthLock {
    fn drop(&mut self) {
        let _ = fs2::FileExt::unlock(&self.0);
    }
}
