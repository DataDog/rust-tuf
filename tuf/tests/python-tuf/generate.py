#!/usr/bin/env python3
"""Generate the python-tuf signed repositories used by `tests/crypto_backend.rs`.

The repositories are signed by the TUF reference implementation, so the Rust
client is exercised against metadata it did not produce itself. One repository
is signed with ECDSA P-256 keys (`ecdsa` / `ecdsa-sha2-nistp256`, PEM SPKI
public keys) and one with Ed25519 keys.

Each repository has consistent snapshots enabled, two root versions (so the
client walks the root chain), and one target file hashed with SHA-256 and
SHA-512.

Keys are derived from fixed constants so key IDs are stable across runs; ECDSA
signatures are randomized, so regenerating still rewrites the signatures.

Usage (from this directory):

    python3 -m venv venv
    venv/bin/pip install 'tuf==6.0.0' 'securesystemslib[crypto]==1.6.0'
    venv/bin/python generate.py
"""

import hashlib
import shutil
from datetime import datetime, timezone
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric import ec, ed25519
from securesystemslib.signer import CryptoSigner
from tuf.api.metadata import (
    MetaFile,
    Metadata,
    Root,
    Snapshot,
    TargetFile,
    Targets,
    Timestamp,
)
from tuf.api.serialization.json import JSONSerializer

SPEC_VERSION = "1.0.0"
EXPIRES = datetime(2100, 1, 1, tzinfo=timezone.utc)
ROLES = ("root", "targets", "snapshot", "timestamp")
TARGET_PATH = "foo/bar.txt"
TARGET_DATA = b"hello from python-tuf\n"
HASH_ALGS = ["sha256", "sha512"]

HERE = Path(__file__).resolve().parent


def ecdsa_signer(index: int) -> CryptoSigner:
    scalar = int.from_bytes(hashlib.sha256(b"rust-tuf ecdsa %d" % index).digest(), "big")
    return CryptoSigner(ec.derive_private_key(scalar, ec.SECP256R1()))


def ed25519_signer(index: int) -> CryptoSigner:
    seed = hashlib.sha256(b"rust-tuf ed25519 %d" % index).digest()
    return CryptoSigner(ed25519.Ed25519PrivateKey.from_private_bytes(seed))


def write(path: Path, md: Metadata) -> bytes:
    data = md.to_bytes(JSONSerializer(compact=False))
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(data)
    return data


def generate(name: str, make_signer) -> None:
    out = HERE / name
    shutil.rmtree(out, ignore_errors=True)
    metadata_dir = out / "metadata"
    targets_dir = out / "targets"

    signers = {role: make_signer(i) for i, role in enumerate(ROLES)}

    root = Root(
        version=1,
        spec_version=SPEC_VERSION,
        expires=EXPIRES,
        consistent_snapshot=True,
    )
    for role, signer in signers.items():
        root.add_key(signer.public_key, role)

    root_md = Metadata(root)
    root_md.sign(signers["root"])
    write(metadata_dir / "1.root.json", root_md)

    root_md.signed.version = 2
    root_md.signatures.clear()
    root_md.sign(signers["root"])
    write(metadata_dir / "2.root.json", root_md)

    target = TargetFile.from_data(TARGET_PATH, TARGET_DATA, HASH_ALGS)
    for digest in target.hashes.values():
        dirname, filename = TARGET_PATH.rsplit("/", 1)
        path = targets_dir / dirname / f"{digest}.{filename}"
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(TARGET_DATA)

    targets_md = Metadata(
        Targets(
            version=1,
            spec_version=SPEC_VERSION,
            expires=EXPIRES,
            targets={TARGET_PATH: target},
        )
    )
    targets_md.sign(signers["targets"])
    targets_bytes = write(metadata_dir / "1.targets.json", targets_md)

    snapshot_md = Metadata(
        Snapshot(
            version=1,
            spec_version=SPEC_VERSION,
            expires=EXPIRES,
            meta={"targets.json": MetaFile.from_data(1, targets_bytes, HASH_ALGS)},
        )
    )
    snapshot_md.sign(signers["snapshot"])
    snapshot_bytes = write(metadata_dir / "1.snapshot.json", snapshot_md)

    timestamp_md = Metadata(
        Timestamp(
            version=1,
            spec_version=SPEC_VERSION,
            expires=EXPIRES,
            snapshot_meta=MetaFile.from_data(1, snapshot_bytes, HASH_ALGS),
        )
    )
    timestamp_md.sign(signers["timestamp"])
    write(metadata_dir / "timestamp.json", timestamp_md)


if __name__ == "__main__":
    generate("ecdsa", ecdsa_signer)
    generate("ed25519", ed25519_signer)
