//! File snapshot store: layout, modes, durability, leftovers.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

mod common;

use browserx_core::{Error, ProfileId, SnapshotStore};
use browserx_store::FileSnapshotStore;
use common::{sealed_snapshot, test_sealer};

#[tokio::test]
async fn layout_modes_and_restart() {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path().join("snaps");
    let sealer = test_sealer();
    let profile = ProfileId::new();
    {
        let store = FileSnapshotStore::new(root.clone()).unwrap();
        store
            .put(&sealed_snapshot(&sealer, profile, 1))
            .await
            .unwrap();
        store
            .put(&sealed_snapshot(&sealer, profile, 2))
            .await
            .unwrap();
    }
    let pdir = root.join(profile.prefixed());
    let mut names: Vec<String> = std::fs::read_dir(&pdir)
        .unwrap()
        .map(|e| e.unwrap().file_name().into_string().unwrap())
        .collect();
    names.sort();
    assert_eq!(
        names,
        vec![
            format!("{:020}.meta.json", 1),
            format!("{:020}.snap", 1),
            format!("{:020}.meta.json", 2),
            format!("{:020}.snap", 2),
        ]
    );
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        for n in &names {
            let mode = std::fs::metadata(pdir.join(n))
                .unwrap()
                .permissions()
                .mode()
                & 0o777;
            assert_eq!(mode, 0o600, "{n}");
        }
        assert_eq!(
            std::fs::metadata(&pdir).unwrap().permissions().mode() & 0o777,
            0o700
        );
        assert_eq!(
            std::fs::metadata(&root).unwrap().permissions().mode() & 0o777,
            0o700
        );
    }
    // plaintext never lands on disk
    let raw = std::fs::read(pdir.join(format!("{:020}.snap", 2))).unwrap();
    assert!(!String::from_utf8_lossy(&raw).contains("synthetic"));

    let reopened = FileSnapshotStore::new(root).unwrap();
    let latest = reopened.latest(profile).await.unwrap().unwrap();
    assert_eq!(latest.meta.version, 2);
    assert!(sealer.open(&latest).is_ok());
    assert!(matches!(
        reopened.put(&sealed_snapshot(&sealer, profile, 2)).await,
        Err(Error::Conflict(_))
    ));
}

#[tokio::test]
async fn uncommitted_leftovers_are_invisible_and_swept() {
    let dir = tempfile::tempdir().unwrap();
    let store = FileSnapshotStore::new(dir.path().to_path_buf()).unwrap();
    let sealer = test_sealer();
    let profile = ProfileId::new();
    store
        .put(&sealed_snapshot(&sealer, profile, 1))
        .await
        .unwrap();

    let pdir = dir.path().join(profile.prefixed());
    std::fs::write(
        pdir.join(format!("{:020}.snap", 2)),
        b"payload without metadata",
    )
    .unwrap();
    std::fs::write(
        pdir.join(".00000000000000000003.snap.tmp-deadbeef"),
        b"partial",
    )
    .unwrap();

    assert_eq!(store.list(profile).await.unwrap().len(), 1);
    assert_eq!(
        store.latest(profile).await.unwrap().unwrap().meta.version,
        1
    );
    store.prune(profile, 5).await.unwrap();
    let remaining: Vec<_> = std::fs::read_dir(&pdir).unwrap().collect();
    assert_eq!(remaining.len(), 2, "only v1 snap + meta remain");
    // the orphan version number is usable again
    store
        .put(&sealed_snapshot(&sealer, profile, 2))
        .await
        .unwrap();
}

#[tokio::test]
async fn corruption_is_reported_not_hidden() {
    let dir = tempfile::tempdir().unwrap();
    let store = FileSnapshotStore::new(dir.path().to_path_buf()).unwrap();
    let sealer = test_sealer();
    let profile = ProfileId::new();
    store
        .put(&sealed_snapshot(&sealer, profile, 1))
        .await
        .unwrap();
    let snap = dir
        .path()
        .join(profile.prefixed())
        .join(format!("{:020}.snap", 1));
    let mut bytes = std::fs::read(&snap).unwrap();
    bytes.truncate(bytes.len() - 1);
    std::fs::write(&snap, bytes).unwrap();
    assert!(matches!(
        store.latest(profile).await,
        Err(Error::Storage(_))
    ));
}
