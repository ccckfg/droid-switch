use super::*;
use aes_gcm::aead::rand_core::RngCore;
use aes_gcm::aead::OsRng;
use aes_gcm::AeadCore;
use aes_gcm::Aes256Gcm;

pub fn make_jwt(email: &str, exp: i64) -> String {
    let h = B64URL.encode(br#"{"alg":"none","typ":"JWT"}"#);
    let c = serde_json::json!({"email": email, "sub": email, "exp": exp});
    let p = B64URL.encode(serde_json::to_vec(&c).unwrap());
    format!("{h}.{p}.{}", B64URL.encode(b"s"))
}

/// Write a synthetic v2 auth bundle to `dir`.
pub fn write_synthetic_bundle(dir: &Path, email: &str, exp: i64) {
    let auth_json =
        serde_json::json!({"access_token": make_jwt(email, exp), "refresh_token": "rt"})
            .to_string();
    let mut key = [0u8; 32];
    OsRng.fill_bytes(&mut key);
    let cipher = Aes256Gcm::new_from_slice(&key).unwrap();
    let nonce = Aes256Gcm::generate_nonce(&mut OsRng);
    let ct_with_tag = cipher.encrypt(&nonce, auth_json.as_bytes()).unwrap();
    let (ct, tag) = ct_with_tag.split_at(ct_with_tag.len() - 16);

    let content = format!(
        "{}:{}:{}",
        B64.encode(nonce),
        B64.encode(tag),
        B64.encode(ct)
    );
    fs::create_dir_all(dir).unwrap();
    fs::write(dir.join("auth.v2.file"), content).unwrap();
    fs::write(dir.join("auth.v2.key"), B64.encode(key)).unwrap();
}

/// Like `write_synthetic_bundle` but uses a 16-byte IV.
pub fn write_synthetic_bundle_16iv(dir: &Path, email: &str, exp: i64) {
    let auth_json =
        serde_json::json!({"access_token": make_jwt(email, exp), "refresh_token": "r"}).to_string();
    let mut key = [0u8; 32];
    OsRng.fill_bytes(&mut key);
    let mut iv = [0u8; 16];
    OsRng.fill_bytes(&mut iv);

    let cipher = Aes256Gcm16::new_from_slice(&key).unwrap();
    let nonce = GenericArray::<u8, U16>::from_slice(&iv);
    let ct_with_tag = cipher.encrypt(nonce, auth_json.as_bytes()).unwrap();
    let (ct, tag) = ct_with_tag.split_at(ct_with_tag.len() - 16);

    let content = format!("{}:{}:{}", B64.encode(iv), B64.encode(tag), B64.encode(ct));
    fs::create_dir_all(dir).unwrap();
    fs::write(dir.join("auth.v2.file"), content).unwrap();
    fs::write(dir.join("auth.v2.key"), B64.encode(key)).unwrap();
}

/// Write a synthetic keyring bundle to `dir` and return the base64-encoded key.
pub fn write_synthetic_keyring_bundle(dir: &Path, email: &str, exp: i64) -> String {
    let auth_json =
        serde_json::json!({"access_token": make_jwt(email, exp), "refresh_token": "r"}).to_string();
    let mut key = [0u8; 32];
    OsRng.fill_bytes(&mut key);
    let cipher = Aes256Gcm::new_from_slice(&key).unwrap();
    let nonce = Aes256Gcm::generate_nonce(&mut OsRng);
    let ct_with_tag = cipher.encrypt(&nonce, auth_json.as_bytes()).unwrap();
    let (ct, tag) = ct_with_tag.split_at(ct_with_tag.len() - 16);

    let content = format!(
        "{}:{}:{}",
        B64.encode(nonce),
        B64.encode(tag),
        B64.encode(ct)
    );
    fs::create_dir_all(dir).unwrap();
    fs::write(dir.join("auth.v2.keyring"), content).unwrap();
    B64.encode(key)
}

/// Write a legacy plaintext `auth.encrypted` file (no v2 bundle).
pub fn write_legacy_bundle(dir: &Path, email: &str, exp: i64) {
    let body =
        serde_json::json!({"access_token": make_jwt(email, exp), "refresh_token": "r"}).to_string();
    fs::create_dir_all(dir).unwrap();
    fs::write(dir.join("auth.encrypted"), body).unwrap();
}
