// Design: two separate keypairs — Ed25519 for signing (identity/auth) and age for
// encryption (confidentiality). Separated because signing keys need to be public
// while encryption keys rotate independently. age chosen over GPG/NaCl because it
// has no config, no key format wars, and works as a library without shelling out.

use std::fs;
use std::io::{Read, Write as IoWrite};
use std::path::Path;

use age::secrecy::ExposeSecret;
use anyhow::Result;
use base64::{engine::general_purpose::STANDARD as BASE64, Engine as _};
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use rand::rngs::OsRng;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

const KEY_DIR: &str = ".keys";

// --- Signed message format ---

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct SignedMessage {
    pub from: String,
    pub timestamp: String,
    pub message: String,
    pub signature: String,
    #[serde(rename = "publicKey")]
    pub public_key: String,
    /// Sender's age public key — lets recipient encrypt replies without registry lookup
    #[serde(rename = "encryptionKey", skip_serializing_if = "Option::is_none")]
    pub encryption_key: Option<String>,
    /// If true, `message` is base64(age-encrypted ciphertext)
    #[serde(default)]
    pub encrypted: bool,
}

// --- Keyring entry (GPG-style) ---

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct KeyringEntry {
    /// Human-readable name (e.g. "wisp")
    pub name: String,
    /// Address: agent-name@hostname (e.g. "wisp@alice.local")
    pub address: String,
    /// Ed25519 signing key (hex)
    #[serde(rename = "signingKey")]
    pub signing_key: String,
    /// age recipient key (age1...)
    #[serde(rename = "encryptionKey", skip_serializing_if = "Option::is_none")]
    pub encryption_key: Option<String>,
    /// SHA-256 fingerprint of signing key
    pub fingerprint: String,
    pub trusted: bool,
    /// Subscribed to this agent's broadcasts
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub subscribed: Option<bool>,
    /// Relationship: "internal" (same org) or "external" (partner/vendor)
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub relationship: Option<String>,
    /// Private note about this peer (never shared, local CRM)
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub note: Option<String>,
    pub added: String,
}

// --- Key generation ---

pub fn generate_keys(store_root: &Path) -> Result<(String, String)> {
    let key_dir = store_root.join(KEY_DIR);
    fs::create_dir_all(&key_dir)?;

    // Ed25519 signing keypair
    let signing_key = SigningKey::generate(&mut OsRng);
    let verifying_key = signing_key.verifying_key();
    let private_hex = hex::encode(signing_key.to_bytes());
    let public_hex = hex::encode(verifying_key.to_bytes());

    fs::write(key_dir.join("private.key"), &private_hex)?;
    fs::write(key_dir.join("public.key"), &public_hex)?;

    // age encryption keypair
    let age_identity = age::x25519::Identity::generate();
    let age_recipient = age_identity.to_public();
    let age_secret = age_identity.to_string();
    let age_public = age_recipient.to_string();

    fs::write(key_dir.join("age.key"), age_secret.expose_secret())?;
    fs::write(key_dir.join("age.pub"), &age_public)?;

    // Restrictive permissions on private keys
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(key_dir.join("private.key"), fs::Permissions::from_mode(0o600))?;
        fs::set_permissions(key_dir.join("age.key"), fs::Permissions::from_mode(0o600))?;
    }

    Ok((public_hex, age_public))
}

// --- Fingerprint ---

/// SHA-256 fingerprint of a public key, truncated to 16 bytes and colon-grouped.
/// Mimics GPG short fingerprints so humans can verify key identity over side channels
/// (voice, chat) without comparing 64-char hex strings.
pub fn fingerprint(public_key: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(public_key.as_bytes());
    let hash = hasher.finalize();
    hash.iter()
        .take(16)
        .map(|b| format!("{:02X}", b))
        .collect::<Vec<_>>()
        .chunks(2)
        .map(|c| c.join(""))
        .collect::<Vec<_>>()
        .join(":")
}

// --- Signing ---

fn load_signing_key(store_root: &Path) -> Result<SigningKey> {
    let hex_str = fs::read_to_string(store_root.join(KEY_DIR).join("private.key"))?;
    let bytes = hex::decode(hex_str.trim())?;
    let arr: [u8; 32] = bytes
        .try_into()
        .map_err(|_| anyhow::anyhow!("Invalid signing key length"))?;
    Ok(SigningKey::from_bytes(&arr))
}

fn load_public_key(store_root: &Path) -> Result<String> {
    Ok(fs::read_to_string(store_root.join(KEY_DIR).join("public.key"))?.trim().to_string())
}

pub fn load_age_recipient(store_root: &Path) -> Result<String> {
    Ok(fs::read_to_string(store_root.join(KEY_DIR).join("age.pub"))?.trim().to_string())
}

fn load_age_identity(store_root: &Path) -> Result<age::x25519::Identity> {
    let s = fs::read_to_string(store_root.join(KEY_DIR).join("age.key"))?;
    s.trim()
        .parse()
        .map_err(|_| anyhow::anyhow!("Invalid age identity"))
}

/// Sign a raw challenge string — used for outbox authentication.
/// Returns (signature_base64, public_key_hex) without the full SignedMessage envelope.
pub fn sign_challenge(store_root: &Path, challenge: &str) -> Result<(String, String)> {
    let signing_key = load_signing_key(store_root)?;
    let public_key = load_public_key(store_root)?;
    let signature = signing_key.sign(challenge.as_bytes());
    Ok((BASE64.encode(signature.to_bytes()), public_key))
}

pub fn sign_message(store_root: &Path, from: &str, message: &str) -> Result<SignedMessage> {
    let signing_key = load_signing_key(store_root)?;
    let public_key = load_public_key(store_root)?;
    let encryption_key = load_age_recipient(store_root).ok();
    let timestamp = chrono::Utc::now().to_rfc3339();

    let payload = format!("{}\n{}\n{}", from, timestamp, message);
    let signature = signing_key.sign(payload.as_bytes());

    Ok(SignedMessage {
        from: from.to_string(),
        timestamp,
        message: message.to_string(),
        signature: BASE64.encode(signature.to_bytes()),
        public_key,
        encryption_key,
        encrypted: false,
    })
}

/// Encrypt-then-sign: encrypt plaintext with recipient's age key, then sign the
/// ciphertext. This ordering matters — signing cleartext then encrypting leaks the
/// ability to strip encryption and replay the signed plaintext. By signing the
/// ciphertext, the signature is only valid for this specific encrypted envelope.
pub fn sign_and_encrypt(
    store_root: &Path,
    from: &str,
    plaintext: &str,
    recipient_age_key: &str,
) -> Result<SignedMessage> {
    let ciphertext = age_encrypt(plaintext.as_bytes(), recipient_age_key)?;
    let encoded = BASE64.encode(&ciphertext);

    let signing_key = load_signing_key(store_root)?;
    let public_key = load_public_key(store_root)?;
    let encryption_key = load_age_recipient(store_root).ok();
    let timestamp = chrono::Utc::now().to_rfc3339();

    let payload = format!("{}\n{}\n{}", from, timestamp, encoded);
    let signature = signing_key.sign(payload.as_bytes());

    Ok(SignedMessage {
        from: from.to_string(),
        timestamp,
        message: encoded,
        signature: BASE64.encode(signature.to_bytes()),
        public_key,
        encryption_key,
        encrypted: true,
    })
}

pub fn verify_message(signed: &SignedMessage) -> bool {
    let Ok(key_bytes) = hex::decode(signed.public_key.trim()) else {
        return false;
    };
    let Ok(arr): Result<[u8; 32], _> = key_bytes.try_into() else {
        return false;
    };
    let Ok(verifying_key) = VerifyingKey::from_bytes(&arr) else {
        return false;
    };
    let Ok(sig_bytes) = BASE64.decode(&signed.signature) else {
        return false;
    };
    let Ok(sig_arr): Result<[u8; 64], _> = sig_bytes.try_into() else {
        return false;
    };
    let signature = Signature::from_bytes(&sig_arr);
    let payload = format!("{}\n{}\n{}", signed.from, signed.timestamp, signed.message);
    verifying_key.verify(payload.as_bytes(), &signature).is_ok()
}

/// Decrypt an encrypted message's content using our age identity.
pub fn decrypt_message(store_root: &Path, signed: &SignedMessage) -> Result<String> {
    if !signed.encrypted {
        return Ok(signed.message.clone());
    }
    let ciphertext = BASE64.decode(&signed.message)?;
    let plaintext = age_decrypt(&ciphertext, store_root)?;
    String::from_utf8(plaintext).map_err(|e| anyhow::anyhow!("Decrypted content is not UTF-8: {}", e))
}

// --- age encryption primitives ---

fn age_encrypt(plaintext: &[u8], recipient_key: &str) -> Result<Vec<u8>> {
    let recipient: age::x25519::Recipient = recipient_key
        .parse()
        .map_err(|_| anyhow::anyhow!("Invalid age recipient key: {}", recipient_key))?;

    let recipients = std::iter::once(&recipient as &dyn age::Recipient);
    let encryptor = age::Encryptor::with_recipients(recipients)
        .map_err(|_| anyhow::anyhow!("Failed to create age encryptor"))?;

    let mut encrypted = vec![];
    let mut writer = encryptor.wrap_output(&mut encrypted)?;
    writer.write_all(plaintext)?;
    writer.finish()?;
    Ok(encrypted)
}

fn age_decrypt(ciphertext: &[u8], store_root: &Path) -> Result<Vec<u8>> {
    let identity = load_age_identity(store_root)?;

    let decryptor = age::Decryptor::new(ciphertext)
        .map_err(|e| anyhow::anyhow!("Failed to parse age ciphertext: {}", e))?;

    let mut reader = decryptor
        .decrypt(std::iter::once(&identity as &dyn age::Identity))
        .map_err(|e| anyhow::anyhow!("age decryption failed: {}", e))?;

    let mut plaintext = vec![];
    reader.read_to_end(&mut plaintext)?;
    Ok(plaintext)
}

/// Wrap a signed message in XML tags for safe injection into LLM context.
/// XML escaping prevents prompt injection — a malicious `from` field containing
/// `</external_message>` can't break out of the wrapper and forge trust signals.
/// Trust metadata resolved from keyring at display time
#[derive(Debug, Default)]
pub struct MessageTrust {
    pub verified: bool,
    pub trusted: bool,
    pub subscribed: bool,
    pub relationship: Option<String>,  // "internal", "external", or None
    pub note: Option<String>,
}

pub fn wrap_external_message(signed: &SignedMessage, trust: &MessageTrust) -> String {
    let esc = |s: &str| s.replace('&', "&amp;").replace('"', "&quot;").replace('<', "&lt;").replace('>', "&gt;");

    // Build badge string: [VERIFIED] [TRUSTED] [INTERNAL] etc.
    let mut badges = Vec::new();
    if trust.verified { badges.push("VERIFIED"); } else { badges.push("UNVERIFIED"); }
    if trust.trusted { badges.push("TRUSTED"); }
    if trust.subscribed { badges.push("SUBSCRIBED"); }
    if let Some(ref rel) = trust.relationship {
        badges.push(if rel == "internal" { "INTERNAL" } else { "EXTERNAL" });
    }
    let status = badges.join(" ");

    let mut attrs = format!(
        "from=\"{}\" verified=\"{}\" trusted=\"{}\" subscribed=\"{}\" time=\"{}\" status=\"{}\"",
        esc(&signed.from), trust.verified, trust.trusted, trust.subscribed,
        esc(&signed.timestamp), esc(&status)
    );
    if let Some(ref rel) = trust.relationship {
        attrs.push_str(&format!(" relationship=\"{}\"", esc(rel)));
    }
    if let Some(ref note) = trust.note {
        attrs.push_str(&format!(" note=\"{}\"", esc(note)));
    }

    format!(
        "<external_message {}>\n{}\n</external_message>",
        attrs, esc(&signed.message)
    )
}

/// Legacy wrapper for backward compat (verified-only, no trust metadata)
pub fn wrap_external_message_simple(signed: &SignedMessage, verified: bool) -> String {
    let trust = MessageTrust { verified, ..Default::default() };
    wrap_external_message(signed, &trust)
}

// ---------------------------------------------------------------------------
// Shared verification utilities (used by daemon + CLI)
// ---------------------------------------------------------------------------

/// Verify an Ed25519 signature over arbitrary bytes.
/// Used by the daemon for both message verification and outbox challenge auth.
pub fn verify_ed25519_signature(message: &[u8], sig_b64: &str, pubkey_hex: &str) -> bool {
    let Ok(key_bytes) = hex::decode(pubkey_hex.trim()) else { return false };
    let Ok(arr): Result<[u8; 32], _> = key_bytes.try_into() else { return false };
    let Ok(verifying_key) = VerifyingKey::from_bytes(&arr) else { return false };
    let Ok(sig_bytes) = BASE64.decode(sig_b64) else { return false };
    let Ok(sig_arr): Result<[u8; 64], _> = sig_bytes.try_into() else { return false };
    let signature = Signature::from_bytes(&sig_arr);
    verifying_key.verify(message, &signature).is_ok()
}

/// Compute the first 8 hex chars of SHA-256 of a string (used for sender fingerprints).
pub fn sha256_fingerprint_short(input: &str) -> String {
    hex::encode(&Sha256::digest(input.as_bytes())[..4])
}
