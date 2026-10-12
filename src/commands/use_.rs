use super::{ensure_home, fmt_identity};
use crate::auth::{self, accounts, storage::CredentialBundle};
use crate::backup;
use crate::cli::UseArgs;
use crate::factory::identity_from_dir;
use crate::paths::{validate_profile_name, Paths};
use crate::profile;
use crate::state::State;
use anyhow::Result;

pub fn run(paths: &Paths, args: UseArgs) -> Result<()> {
    ensure_home(paths)?;
    let target = &args.name;
    validate_profile_name(target)?;
    if !paths.profile_dir(target).is_dir() {
        anyhow::bail!(
            "profile {:?} does not exist - run `dsw list` to see available profiles",
            target
        );
    }
    let mut state = State::load(&paths.state_file())?;
    // Back up before synchronizing. A manual /login can leave state.active
    // pointing to a different account, so match the actual live identity.
    let backup_path = backup::create(paths, state.active.as_deref())?;
    let outgoing = accounts::capture_live(paths)?;
    if outgoing.iter().any(|name| name == target) {
        state.active = Some(target.clone());
        state.save(&paths.state_file())?;
        println!(
            "already on '{target}'  ({})",
            fmt_identity(&identity_from_dir(&paths.factory))
        );
        return Ok(());
    }
    let mut bundle = CredentialBundle::load(&paths.profile_dir(target))?;
    auth::refresh_if_needed(&mut bundle, false)?;
    if let Err(e) = profile::restore_to_live(paths, target) {
        if let Some(b) = &backup_path {
            let id = b.file_name().unwrap().to_string_lossy();
            backup::restore(paths, &id)?;
        }
        return Err(e.context("switch failed; restored the previous login"));
    }
    state.active = Some(target.clone());
    state.save(&paths.state_file())?;
    println!(
        "-> {}  ({})",
        target,
        fmt_identity(&identity_from_dir(&paths.factory))
    );
    if let Some(p) = backup_path {
        println!("  backup: {}", p.file_name().unwrap().to_string_lossy());
    }
    Ok(())
}
