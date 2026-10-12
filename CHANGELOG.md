# Changelog

## 0.1.4

- Persist both rotated tokens before retrying quota requests, retaining encrypted storage and other credential fields.
- Refresh inactive target credentials before switching and preserve the previous login on failure.
- Match the actual live identity instead of trusting a stale active-profile marker; reject cross-account sync.
- Serialize dsw credential operations and use atomic writes; leave live token rotation to Droid.
- Distinguish access-token expiry from confirmed reauthentication requirements.
- Add isolated HTTP, storage, identity-mismatch, and concurrent-switch regression tests.
- Point installers and repository links to the independently maintained ccckfg repository.


All notable changes to this project will be documented in this file.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project uses semantic versioning.

## [0.1.3] - 2026-04-29

### Added

- Added `dsw sync` to save refreshed live Droid auth back to the active profile.
- Added `dsw sync --all` to save the current live auth to matching saved profiles.

## [0.1.2] - 2026-04-28

### Added

- Added first-run guidance when running `dsw` with no command.
- Improved empty profile list guidance based on whether a Droid login exists.

## [0.1.1] - 2026-04-28

### Changed

- Simplified `dsw list` output.
- Hid internal rescue profiles from user-facing profile lists.

## [0.1.0] - 2026-04-28

### Added

- Initial open-source release.
- Profile import, add, use, list, status, remove, and rename commands.
- Automatic backups before account switches.
- Backup list, restore, and prune commands.
- Doctor command for installation and token checks.
- GitHub release workflow with macOS, Linux, and Windows binaries.
