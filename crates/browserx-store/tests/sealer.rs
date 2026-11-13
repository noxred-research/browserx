//! Sealer: encryption, binding, key files.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

mod common;

use browserx_core::{Error, Generation, ProfileId, SessionId};
use browserx_store::Sealer;
use common::{sample_state, sealed_snapshot, test_sealer};

#[test]
fn round_trip_and_metadata_filled() {
    let sealer = test_sealer();
    let snap = sealed_snapshot(&sealer, ProfileId::new(), 7);
    assert_eq!(snap.meta.key_id, "0badc0de");
    assert_eq!(snap.meta.size, snap.sealed.len() as u64);
    assert_eq!(sealer.open(&snap).unwrap(), sample_state("v7"));
    assert!(!String::from_utf8_lossy(&snap.sealed).contains("synthetic-v7"));
}

#[test]
fn nonces_are_random() {
    let sealer = test_sealer();
    let p = ProfileId::new();
    let a = sealed_snapshot(&sealer, p, 1);
    let b = sealed_snapshot(&sealer, p, 1);
    assert_ne!(a.sealed[..12], b.sealed[..12]);
}

#[test]
fn wrong_key_tampering_and_truncation_fail() {
    let sealer = test_sealer();
    let snap = sealed_snapshot(&sealer, ProfileId::new(), 1);

    let other = Sealer::new("0badc0de".into(), [1u8; 32]);
    assert!(matches!(other.open(&snap), Err(Error::Crypto(_))));

    let renamed = Sealer::new("feedface".into(), [42u8; 32]);
    assert!(matches!(renamed.open(&snap), Err(Error::Crypto(_))));

    for idx in [0, 12, snap.sealed.len() - 1] {
        let mut t = snap.clone();
        t.sealed[idx] ^= 1;
        assert!(
            matches!(sealer.open(&t), Err(Error::Crypto(_))),
            "flip at {idx}"
        );
    }
    let mut short = snap.clone();
    short.sealed.truncate(20);
    assert!(matches!(sealer.open(&short), Err(Error::Crypto(_))));
}

#[test]
fn metadata_is_bound_to_the_ciphertext() {
    let sealer = test_sealer();
    let snap = sealed_snapshot(&sealer, ProfileId::new(), 3);

    let mut v = snap.clone();
    v.meta.version = 4;
    assert!(sealer.open(&v).is_err());
    let mut p = snap.clone();
    p.meta.profile_id = ProfileId::new();
    assert!(sealer.open(&p).is_err());
    let mut s = snap.clone();
    s.meta.session_id = SessionId::new();
    assert!(sealer.open(&s).is_err());
    let mut g = snap.clone();
    g.meta.generation = Generation(2);
    assert!(sealer.open(&g).is_err());
    // fields outside the AAD do not matter
    let mut t = snap.clone();
    t.meta.created_at += time::Duration::days(1);
    assert!(sealer.open(&t).is_ok());
}

#[test]
fn debug_hides_key_material() {
    let text = format!("{:?}", Sealer::new("0badc0de".into(), [42u8; 32]));
    assert!(text.contains("0badc0de"));
    assert!(!text.contains("42"));
}

#[test]
fn key_file_round_trip_and_refuses_overwrite() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("keys").join("snapshot.key");
    Sealer::generate_key_file(&path).unwrap();
    let text = std::fs::read_to_string(&path).unwrap();
    let mut lines = text.lines();
    assert_eq!(lines.next(), Some("browserx-snapshot-key v1"));
    assert!(lines.next().unwrap().starts_with("key_id="));
    assert!(lines.next().unwrap().starts_with("key="));
    assert!(text.ends_with('\n'));
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(
            std::fs::metadata(&path).unwrap().permissions().mode() & 0o777,
            0o600
        );
    }
    assert!(matches!(
        Sealer::generate_key_file(&path),
        Err(Error::Conflict(_))
    ));
    assert_eq!(std::fs::read_to_string(&path).unwrap(), text);

    let a = Sealer::from_key_file(&path).unwrap();
    let b = Sealer::from_key_file(&path).unwrap();
    assert_eq!(a.key_id().len(), 8);
    let snap = sealed_snapshot(&a, ProfileId::new(), 1);
    assert_eq!(b.open(&snap).unwrap(), sample_state("v1"));

    let other = dir.path().join("other.key");
    Sealer::generate_key_file(&other).unwrap();
    let c = Sealer::from_key_file(&other).unwrap();
    assert_ne!(c.key_id(), a.key_id());
}

fn write_key(dir: &std::path::Path, name: &str, body: &str) -> std::path::PathBuf {
    let path = dir.join(name);
    std::fs::write(&path, body).unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
    }
    path
}

#[test]
fn key_file_rejections() {
    let dir = tempfile::tempdir().unwrap();
    let good_key = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=";
    let ok = write_key(
        dir.path(),
        "ok",
        &format!("browserx-snapshot-key v1\nkey_id=0123abcd\nkey={good_key}\n"),
    );
    assert!(Sealer::from_key_file(&ok).is_ok());

    let cases = [
        (
            "newer",
            format!("browserx-snapshot-key v2\nkey_id=0123abcd\nkey={good_key}\n"),
        ),
        (
            "magic",
            format!("something-else v1\nkey_id=0123abcd\nkey={good_key}\n"),
        ),
        (
            "short",
            "browserx-snapshot-key v1\nkey_id=0123abcd\nkey=AAAA\n".to_owned(),
        ),
        (
            "b64",
            "browserx-snapshot-key v1\nkey_id=0123abcd\nkey=!!!\n".to_owned(),
        ),
        (
            "id",
            format!("browserx-snapshot-key v1\nkey_id=zz\nkey={good_key}\n"),
        ),
        (
            "noid",
            format!("browserx-snapshot-key v1\nkey={good_key}\n"),
        ),
        (
            "nokey",
            "browserx-snapshot-key v1\nkey_id=0123abcd\n".to_owned(),
        ),
        (
            "extra",
            format!("browserx-snapshot-key v1\nkey_id=0123abcd\nkey={good_key}\nfoo=bar\n"),
        ),
        ("empty", String::new()),
    ];
    for (name, body) in cases {
        let p = write_key(dir.path(), name, &body);
        match Sealer::from_key_file(&p) {
            Err(Error::Crypto(_)) => {}
            Err(other) => panic!("{name}: unexpected error {other:?}"),
            Ok(_) => panic!("{name}: accepted"),
        }
    }
    let err = Sealer::from_key_file(&dir.path().join("newer")).unwrap_err();
    assert!(err.to_string().contains("newer"));
    assert!(Sealer::from_key_file(&dir.path().join("missing")).is_err());
}

#[cfg(unix)]
#[test]
fn world_readable_key_file_is_refused() {
    use std::os::unix::fs::PermissionsExt;
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("snapshot.key");
    Sealer::generate_key_file(&path).unwrap();
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();
    assert!(matches!(
        Sealer::from_key_file(&path),
        Err(Error::Crypto(_))
    ));
}
