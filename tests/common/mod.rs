#![allow(dead_code)]
use std::fs;
use std::path::Path;

use assert_cmd::Command;
use dsw::factory::testing::write_synthetic_bundle;
use tempfile::TempDir;

pub struct Sandbox {
    pub _td: TempDir,
    pub home: std::path::PathBuf,
    pub factory: std::path::PathBuf,
}

impl Sandbox {
    pub fn new() -> Self {
        let td = TempDir::new().unwrap();
        let home = td.path().join("dsw");
        let factory = td.path().join("factory");
        fs::create_dir_all(&factory).unwrap();
        Self {
            _td: td,
            home,
            factory,
        }
    }

    pub fn cmd(&self) -> Command {
        let mut c = Command::cargo_bin("dsw").unwrap();
        c.env("DSW_HOME", &self.home)
            .env("FACTORY_DIR", &self.factory)
            .env("DSW_NO_NETWORK", "1")
            // Make sure we don't accidentally pick up the user's PATH droid:
            .env_remove("HOME");
        c
    }

    pub fn write_live(&self, email: &str) {
        // Wipe and rewrite.
        for f in ["auth.v2.file", "auth.v2.key", "auth.encrypted"] {
            let _ = fs::remove_file(self.factory.join(f));
        }
        write_synthetic_bundle(&self.factory, email, 1_900_000_000);
    }
}

pub fn read_live(factory: &Path) -> Vec<u8> {
    fs::read(factory.join("auth.v2.file")).unwrap()
}

pub fn read_profile(home: &Path, name: &str) -> Vec<u8> {
    fs::read(home.join("profiles").join(name).join("auth.v2.file")).unwrap()
}
