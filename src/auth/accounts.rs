//! Match profiles to the actual live identity, never only the active marker.

use anyhow::{bail, Result};

use crate::factory::{identity_from_dir, Identity};
use crate::paths::Paths;
use crate::profile;

pub fn identities_match(a: &Identity, b: &Identity) -> bool {
    match (&a.subject, &b.subject) {
        (Some(a), Some(b)) => a == b,
        _ => match (&a.email, &b.email) {
            (Some(a), Some(b)) => a.eq_ignore_ascii_case(b),
            _ => false,
        },
    }
}

pub fn sync_matching_live(paths: &Paths, name: &str) -> Result<bool> {
    let live = identity_from_dir(&paths.factory);
    let saved = identity_from_dir(&paths.profile_dir(name));
    if !identities_match(&live, &saved) {
        return Ok(false);
    }
    profile::snapshot_live_checked(paths, name, &live)?;
    let captured = identity_from_dir(&paths.profile_dir(name));
    if !identities_match(&live, &captured) {
        bail!(
            "Droid changed accounts while credentials were being saved; retry after closing Droid"
        );
    }
    Ok(true)
}

/// Save refreshed outgoing credentials into every alias of that identity.
pub fn capture_live(paths: &Paths) -> Result<Vec<String>> {
    let mut matched = Vec::new();
    for name in profile::list(paths)? {
        if sync_matching_live(paths, &name)? {
            matched.push(name);
        }
    }
    Ok(matched)
}
