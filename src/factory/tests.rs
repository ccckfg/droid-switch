use super::testing::*;
use super::*;
use tempfile::TempDir;

#[test]
fn roundtrip_v2_bundle() {
    let td = TempDir::new().unwrap();
    write_synthetic_bundle(td.path(), "alice@example.com", 1_900_000_000);
    let id = identity_from_dir(td.path());
    assert_eq!(id.email.as_deref(), Some("alice@example.com"));
    assert!(id.expires_at.is_some());
}

#[test]
fn legacy_fallback() {
    let td = TempDir::new().unwrap();
    write_legacy_bundle(td.path(), "bob@example.com", 1_900_000_000);
    let id = identity_from_dir(td.path());
    assert_eq!(id.email.as_deref(), Some("bob@example.com"));
}

#[test]
fn unknown_when_empty() {
    let td = TempDir::new().unwrap();
    let id = identity_from_dir(td.path());
    assert_eq!(id, Identity::unknown());
}

#[test]
fn roundtrip_v2_bundle_with_16_byte_iv() {
    let td = TempDir::new().unwrap();
    write_synthetic_bundle_16iv(td.path(), "carol@example.com", 1_900_000_000);
    let id = identity_from_dir(td.path());
    assert_eq!(id.email.as_deref(), Some("carol@example.com"));
}

#[test]
fn roundtrip_keyring_bundle() {
    let td = TempDir::new().unwrap();
    let key_b64 = write_synthetic_keyring_bundle(td.path(), "dave@example.com", 1_900_000_000);
    std::env::set_var(crate::keyring::ENV_KEY_OVERRIDE, &key_b64);
    let id = identity_from_dir(td.path());
    std::env::remove_var(crate::keyring::ENV_KEY_OVERRIDE);
    assert_eq!(id.email.as_deref(), Some("dave@example.com"));
}
