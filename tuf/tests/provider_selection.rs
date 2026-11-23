//! With several backends compiled, TUF must not pick one: the application installs it.
#![cfg(all(feature = "ring", feature = "fips"))]

use tuf::crypto::{self, provider, HashAlgorithm};

#[test]
fn several_backends_need_an_explicit_provider() {
    let err = crypto::calculate_hashes_from_slice(b"abc", &[HashAlgorithm::Sha256]).unwrap_err();
    assert!(matches!(err, tuf::Error::NoCryptoProvider(_)), "{err}");

    crypto::install_default(provider::fips::provider()).unwrap();
    // Installing the same provider again is fine.
    crypto::install_default(provider::fips::provider()).unwrap();
    assert!(matches!(
        crypto::install_default(provider::ring::provider()),
        Err(tuf::Error::CryptoProviderAlreadyInstalled {
            installed: "fips",
            requested: "ring"
        })
    ));

    assert_eq!(crypto::get_default().unwrap().name(), "fips");
    crypto::calculate_hashes_from_slice(b"abc", &[HashAlgorithm::Sha256]).unwrap();
}
