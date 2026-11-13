//! Known-answer tests for signature verification and hashing. These only use the public API, so
//! they must pass unchanged whichever crypto backend the crate is built with.

use assert_matches::assert_matches;
use data_encoding::HEXLOWER;
use futures_executor::block_on;
use futures_util::io::AsyncReadExt;
use std::collections::HashMap;
use std::fs;
use std::path::Path;
use tuf::client::{Client, Config};
use tuf::crypto::{
    calculate_hashes_from_reader, calculate_hashes_from_slice, HashAlgorithm, HashValue, PublicKey,
    Signature,
};
use tuf::interchange::Json;
use tuf::metadata::{
    Metadata, MetadataPath, MetadataVersion, RawSignedMetadata, RootMetadata, TargetPath,
};
use tuf::repository::{EphemeralRepository, RepositoryStorage};
use tuf::Error;

const ED25519_PUBLIC_KEY: &[u8] = include_bytes!("./ed25519/ed25519-1.pub");

/// Signature by `ed25519-1` over `b"test"`.
const ED25519_SIG_OVER_TEST: &str = "fe4d13b2a73c033a1de7f5107b205fc7ba0e1566cb95b92349cae6aa4538\
                                     956013bfe0f7bf977cb072bb65e8782b5f33a0573fe78816299a017ca5ba\
                                     559e390c";

const ECDSA_ROOT: &[u8] = include_bytes!("./ecdsa/ecdsa_root.json");
const ECDSA_ROOT_CANONICAL: &[u8] = include_bytes!("./ecdsa/ecdsa_root.canonical");

const SHA256_ABC: &str = "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad";
const SHA512_ABC: &str = "ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a\
                          2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f";
const SHA256_MILLION_A: &str = "cdc76e5c9914fb9281a1c7e284d73e67f1809a48a497200e046d39ccc7112cd0";
const SHA512_MILLION_A: &str = "e718483d0ce769644e2e42c7bc15b4638e1f98b13b2044285632a803afa973eb\
                                de0ff244877ea60a4cb0432ce577c31beb009c5c2c49aa2e4eadb217ad8cc09b";

fn signature(key: &PublicKey, hex: &str) -> Signature {
    serde_json::from_value(serde_json::json!({
        "keyid": key.key_id(),
        "sig": hex,
    }))
    .unwrap()
}

fn expected_hashes(sha256: &str, sha512: &str) -> HashMap<HashAlgorithm, HashValue> {
    HashMap::from([
        (
            HashAlgorithm::Sha256,
            HashValue::new(HEXLOWER.decode(sha256.as_bytes()).unwrap()),
        ),
        (
            HashAlgorithm::Sha512,
            HashValue::new(HEXLOWER.decode(sha512.as_bytes()).unwrap()),
        ),
    ])
}

#[test]
fn ed25519_known_signature_verifies() {
    let key = PublicKey::from_ed25519(ED25519_PUBLIC_KEY).unwrap();
    let sig = signature(&key, ED25519_SIG_OVER_TEST);
    let role = MetadataPath::root();

    assert_matches!(key.verify(&role, b"test", &sig), Ok(()));
    assert_matches!(
        key.verify(&role, b"tesT", &sig),
        Err(Error::BadSignature(r)) if r == role
    );
}

#[test]
fn ecdsa_p256_known_signatures_verify() {
    let root: serde_json::Value = serde_json::from_slice(ECDSA_ROOT).unwrap();
    let keys = root["signed"]["keys"].as_object().unwrap();
    let signatures = root["signatures"].as_array().unwrap();
    assert!(!signatures.is_empty());

    let mut tampered = ECDSA_ROOT_CANONICAL.to_vec();
    let last = tampered.len() - 2;
    tampered[last] ^= 0x01;

    let role = MetadataPath::root();
    for sig in signatures {
        let key: PublicKey =
            serde_json::from_value(keys[sig["keyid"].as_str().unwrap()].clone()).unwrap();
        let sig: Signature = serde_json::from_value(sig.clone()).unwrap();

        assert_matches!(key.verify(&role, ECDSA_ROOT_CANONICAL, &sig), Ok(()));
        assert_matches!(
            key.verify(&role, &tampered, &sig),
            Err(Error::BadSignature(r)) if r == role
        );
    }
}

#[test]
fn sha256_and_sha512_known_digests() {
    let algs = [HashAlgorithm::Sha256, HashAlgorithm::Sha512];
    let million_a = vec![b'a'; 1_000_000];

    assert_eq!(
        calculate_hashes_from_slice(b"abc", &algs).unwrap(),
        expected_hashes(SHA256_ABC, SHA512_ABC),
    );
    assert_eq!(
        calculate_hashes_from_slice(&million_a, &algs).unwrap(),
        expected_hashes(SHA256_MILLION_A, SHA512_MILLION_A),
    );

    let (len, hashes) = block_on(calculate_hashes_from_reader(&million_a[..], &algs)).unwrap();
    assert_eq!(len, 1_000_000);
    assert_eq!(hashes, expected_hashes(SHA256_MILLION_A, SHA512_MILLION_A));
}

/// Loads a python-tuf signed repository from `tests/python-tuf/` into an `EphemeralRepository`.
async fn load_python_tuf_repo(dir: &Path) -> EphemeralRepository<Json> {
    let mut repo = EphemeralRepository::new();

    for entry in fs::read_dir(dir.join("metadata")).unwrap() {
        let path = entry.unwrap().path();
        let name = path.file_name().unwrap().to_str().unwrap();
        let name = name.strip_suffix(".json").unwrap();
        let (version, role) = match name.split_once('.') {
            Some((version, role)) => (MetadataVersion::Number(version.parse().unwrap()), role),
            None => (MetadataVersion::None, name),
        };
        let meta_path = MetadataPath::new(role.to_owned()).unwrap();
        let data = fs::read(&path).unwrap();
        repo.store_metadata(&meta_path, version, &mut data.as_slice())
            .await
            .unwrap();
    }

    let targets_dir = dir.join("targets");
    for entry in walk(&targets_dir) {
        let rel = entry.strip_prefix(&targets_dir).unwrap();
        let rel = rel.to_str().unwrap().replace('\\', "/");
        let data = fs::read(&entry).unwrap();
        repo.store_target(&TargetPath::new(rel).unwrap(), &mut data.as_slice())
            .await
            .unwrap();
    }

    repo
}

fn walk(dir: &Path) -> Vec<std::path::PathBuf> {
    let mut files = vec![];
    for entry in fs::read_dir(dir).unwrap() {
        let path = entry.unwrap().path();
        if path.is_dir() {
            files.extend(walk(&path));
        } else {
            files.push(path);
        }
    }
    files
}

async fn client_update_and_fetch_target(scheme: &str) {
    let dir = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("python-tuf")
        .join(scheme);
    let trusted_root = RawSignedMetadata::<Json, RootMetadata>::new(
        fs::read(dir.join("metadata").join("1.root.json")).unwrap(),
    );
    let target_path = TargetPath::new("foo/bar.txt").unwrap();
    let target_data = b"hello from python-tuf\n";

    let remote = load_python_tuf_repo(&dir).await;
    let mut client = Client::with_trusted_root(
        Config::default(),
        &trusted_root,
        EphemeralRepository::<Json>::new(),
        remote,
    )
    .await
    .unwrap();

    assert!(client.update().await.unwrap());
    assert_eq!(client.database().trusted_root().version(), 2);

    let description = client
        .database()
        .trusted_targets()
        .unwrap()
        .targets()
        .get(&target_path)
        .unwrap()
        .clone();
    assert_eq!(description.length(), target_data.len() as u64);

    let mut fetched = vec![];
    client
        .fetch_target(&target_path)
        .await
        .unwrap()
        .read_to_end(&mut fetched)
        .await
        .unwrap();
    assert_eq!(fetched, target_data);

    let algs: Vec<HashAlgorithm> = description.hashes().keys().cloned().collect();
    assert_eq!(algs.len(), 2);
    assert_eq!(
        &calculate_hashes_from_slice(&fetched, &algs).unwrap(),
        description.hashes(),
    );

    // A target whose bytes don't match the signed hashes must not be accepted.
    for hash in description.hashes().values() {
        client
            .remote_repo_mut()
            .store_target(
                &target_path.with_hash_prefix(hash).unwrap(),
                &mut &b"hello from python-tuF\n"[..],
            )
            .await
            .unwrap();
    }
    let mut fetched = vec![];
    assert!(client
        .fetch_target(&target_path)
        .await
        .unwrap()
        .read_to_end(&mut fetched)
        .await
        .is_err());

    // Timestamp metadata whose signed body was altered must be rejected.
    let mut remote = load_python_tuf_repo(&dir).await;
    let timestamp = fs::read(dir.join("metadata").join("timestamp.json")).unwrap();
    let timestamp = String::from_utf8(timestamp)
        .unwrap()
        .replace("2100-01-01T00:00:00Z", "2099-01-01T00:00:00Z");
    remote
        .store_metadata(
            &MetadataPath::timestamp(),
            MetadataVersion::None,
            &mut timestamp.as_bytes(),
        )
        .await
        .unwrap();
    let mut client = Client::with_trusted_root(
        Config::default(),
        &trusted_root,
        EphemeralRepository::<Json>::new(),
        remote,
    )
    .await
    .unwrap();
    assert_matches!(
        client.update().await,
        Err(Error::MetadataMissingSignatures { role, number_of_valid_signatures: 0, threshold: 1 })
        if role == MetadataPath::timestamp()
    );
}

#[test]
fn client_update_ecdsa_p256_repo() {
    block_on(client_update_and_fetch_target("ecdsa"));
}

#[test]
fn client_update_ed25519_repo() {
    block_on(client_update_and_fetch_target("ed25519"));
}
