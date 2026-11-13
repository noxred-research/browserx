//! API key and snapshot key creation.

use std::io::Write;
use std::path::Path;

use anyhow::{Context, Result, bail};
use browserx_server::key_digest;
use browserx_store::Sealer;
use rand::Rng;

/// A fresh API key: recognizable prefix, 256 random bits.
fn generate_key() -> String {
    let mut bytes = [0u8; 32];
    rand::rng().fill_bytes(&mut bytes);
    format!("bxk_{}", hex::encode(bytes))
}

/// Prints a new API key (once) and the configuration snippet that authorizes it.
pub fn new_api_key(out: &mut impl Write, name: &str, max_sessions: usize) -> Result<()> {
    if name.is_empty()
        || name.len() > 64
        || !name
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.'))
    {
        bail!("key name must be 1-64 characters of letters, digits, `-`, `_` or `.`");
    }
    if max_sessions == 0 {
        bail!("--max-sessions must be positive");
    }
    let key = generate_key();
    writeln!(
        out,
        "API key for `{name}` (shown once; store it in a secret manager):"
    )?;
    writeln!(out, "{key}")?;
    writeln!(out)?;
    writeln!(
        out,
        "Add this to your configuration file (it contains only the key's SHA-256):"
    )?;
    writeln!(out, "[[auth.api_keys]]")?;
    writeln!(out, "name = \"{name}\"")?;
    writeln!(out, "sha256 = \"{}\"", key_digest(&key))?;
    writeln!(out, "max_sessions = {max_sessions}")?;
    Ok(())
}

/// Creates a snapshot encryption key file.
pub fn new_snapshot_key(path: &Path) -> Result<()> {
    if let Some(parent) = path.parent().filter(|p| !p.as_os_str().is_empty()) {
        use std::os::unix::fs::DirBuilderExt;
        std::fs::DirBuilder::new()
            .recursive(true)
            .mode(0o700)
            .create(parent)
            .with_context(|| format!("cannot create {}", parent.display()))?;
    }
    Sealer::generate_key_file(path)
        .with_context(|| format!("cannot create snapshot key {}", path.display()))?;
    Ok(())
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

    use super::*;

    #[test]
    fn snippet_matches_the_printed_key() {
        let mut out = Vec::new();
        new_api_key(&mut out, "dev", 4).unwrap();
        let text = String::from_utf8(out).unwrap();
        let key = text.lines().find(|l| l.starts_with("bxk_")).unwrap();
        assert_eq!(key.len(), 4 + 64);
        assert!(text.contains(&format!("sha256 = \"{}\"", key_digest(key))));
        assert!(text.contains("max_sessions = 4"));
        assert!(
            !text
                .lines()
                .filter(|l| l.contains("sha256"))
                .any(|l| l.contains(key))
        );
    }

    #[test]
    fn bad_names_are_rejected() {
        let mut out = Vec::new();
        assert!(new_api_key(&mut out, "", 1).is_err());
        assert!(new_api_key(&mut out, "has space", 1).is_err());
        assert!(new_api_key(&mut out, "ok", 0).is_err());
    }

    #[test]
    fn snapshot_key_is_created_once() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("nested/snapshot.key");
        new_snapshot_key(&path).unwrap();
        assert!(
            new_snapshot_key(&path).is_err(),
            "must not overwrite an existing key"
        );
    }
}
