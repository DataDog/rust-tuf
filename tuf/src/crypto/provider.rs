//! Crypto providers. Each enabled backend feature compiles one provider; the application picks
//! the one TUF uses with [`install_default`]. With a single backend compiled, it is used
//! without being installed.

use std::fmt;

use crate::crypto::{HashAlgorithm, SignatureScheme};
use crate::error::Result;

/// A running hash computation.
pub trait DigestContext: Send {
    /// Add `data` to the hash.
    fn update(&mut self, data: &[u8]);
    /// Finish and return the digest.
    fn finish(self: Box<Self>) -> Vec<u8>;
}

/// An Ed25519 key pair held by one provider.
pub trait Ed25519Signer: Send + Sync {
    /// The 32-byte public key.
    fn public_key(&self) -> &[u8];
    /// Sign `msg`.
    fn sign(&self, msg: &[u8]) -> Vec<u8>;
}

/// The cryptography TUF uses: signature verification, hashing, and Ed25519 keys.
pub trait CryptoProvider: Send + Sync + fmt::Debug {
    /// The backend feature name: `ring`, `aws-lc-rs`, or `fips`.
    fn name(&self) -> &'static str;
    /// Whether this provider runs on a module in FIPS mode.
    fn fips(&self) -> bool;
    /// `Ok(false)` if `signature` does not verify; `Err` if `scheme` is not supported.
    fn verify(
        &self,
        scheme: &SignatureScheme,
        public_key: &[u8],
        msg: &[u8],
        signature: &[u8],
    ) -> Result<bool>;
    /// Start hashing with `alg`.
    fn digest(&self, alg: &HashAlgorithm) -> Result<Box<dyn DigestContext>>;
    /// Generate an Ed25519 key in PKCS#8 v2.
    fn ed25519_generate_pkcs8(&self) -> Result<Vec<u8>>;
    /// Load an RFC 5958 PKCS#8 v2 Ed25519 key.
    fn ed25519_from_pkcs8(&self, der: &[u8]) -> Result<Box<dyn Ed25519Signer>>;
    /// Load an Ed25519 key from its seed, checked against its public key.
    fn ed25519_from_seed_and_public_key(
        &self,
        seed: &[u8],
        public_key: &[u8],
    ) -> Result<Box<dyn Ed25519Signer>>;
}

macro_rules! backend_provider {
    ($module:ident, $backend:ident, $name:literal, fips = $fips:expr) => {
        #[doc = concat!("The `", $name, "` provider.")]
        pub mod $module {
            use ::$backend::{
                digest,
                rand::SystemRandom,
                signature::{self, KeyPair as _},
            };

            use super::{CryptoProvider, DigestContext, Ed25519Signer};
            use crate::crypto::{HashAlgorithm, SignatureScheme};
            use crate::error::{Error, Result};

            #[derive(Debug)]
            struct Provider;

            static PROVIDER: Provider = Provider;

            /// This backend's provider.
            pub fn provider() -> &'static dyn CryptoProvider {
                &PROVIDER
            }

            struct Digest(digest::Context);

            impl DigestContext for Digest {
                fn update(&mut self, data: &[u8]) {
                    self.0.update(data);
                }

                fn finish(self: Box<Self>) -> Vec<u8> {
                    self.0.finish().as_ref().to_vec()
                }
            }

            struct Signer(signature::Ed25519KeyPair);

            impl Ed25519Signer for Signer {
                fn public_key(&self) -> &[u8] {
                    self.0.public_key().as_ref()
                }

                fn sign(&self, msg: &[u8]) -> Vec<u8> {
                    self.0.sign(msg).as_ref().to_vec()
                }
            }

            impl CryptoProvider for Provider {
                fn name(&self) -> &'static str {
                    $name
                }

                fn fips(&self) -> bool {
                    $fips
                }

                fn verify(
                    &self,
                    scheme: &SignatureScheme,
                    public_key: &[u8],
                    msg: &[u8],
                    sig: &[u8],
                ) -> Result<bool> {
                    let alg: &'static dyn signature::VerificationAlgorithm = match scheme {
                        SignatureScheme::Ed25519 => &signature::ED25519,
                        #[cfg(feature = "unstable_rsa")]
                        SignatureScheme::RsaSsaPssSha256 => &signature::RSA_PSS_2048_8192_SHA256,
                        #[cfg(feature = "unstable_rsa")]
                        SignatureScheme::RsaSsaPssSha512 => &signature::RSA_PSS_2048_8192_SHA512,
                        SignatureScheme::EcdsaSha2Nistp256 => &signature::ECDSA_P256_SHA256_ASN1,
                        SignatureScheme::Unknown(s) => {
                            return Err(Error::UnknownSignatureScheme(s.clone()));
                        }
                    };
                    Ok(signature::UnparsedPublicKey::new(alg, public_key)
                        .verify(msg, sig)
                        .is_ok())
                }

                fn digest(&self, alg: &HashAlgorithm) -> Result<Box<dyn DigestContext>> {
                    let alg = match alg {
                        HashAlgorithm::Sha256 => &digest::SHA256,
                        HashAlgorithm::Sha512 => &digest::SHA512,
                        HashAlgorithm::Unknown(s) => {
                            return Err(Error::IllegalArgument(format!(
                                "Unknown hash algorithm: {}",
                                s
                            )));
                        }
                    };
                    Ok(Box::new(Digest(digest::Context::new(alg))))
                }

                fn ed25519_generate_pkcs8(&self) -> Result<Vec<u8>> {
                    signature::Ed25519KeyPair::generate_pkcs8(&SystemRandom::new())
                        .map(|bytes| bytes.as_ref().to_vec())
                        .map_err(|_| Error::Opaque("Failed to generate Ed25519 key".into()))
                }

                fn ed25519_from_pkcs8(&self, der: &[u8]) -> Result<Box<dyn Ed25519Signer>> {
                    signature::Ed25519KeyPair::from_pkcs8(der)
                        .map(|key| Box::new(Signer(key)) as Box<dyn Ed25519Signer>)
                        .map_err(|_| Error::Encoding("Could not parse key as PKCS#8v2".into()))
                }

                fn ed25519_from_seed_and_public_key(
                    &self,
                    seed: &[u8],
                    public_key: &[u8],
                ) -> Result<Box<dyn Ed25519Signer>> {
                    signature::Ed25519KeyPair::from_seed_and_public_key(seed, public_key)
                        .map(|key| Box::new(Signer(key)) as Box<dyn Ed25519Signer>)
                        .map_err(|err| Error::Encoding(err.to_string()))
                }
            }
        }
    };
}

#[cfg(feature = "ring")]
backend_provider!(ring, ring, "ring", fips = false);
#[cfg(feature = "aws-lc-rs")]
backend_provider!(aws_lc_rs, aws_lc_rs, "aws-lc-rs", fips = false);
#[cfg(feature = "fips")]
backend_provider!(
    fips,
    aws_lc_rs_fips,
    "fips",
    fips = ::aws_lc_rs_fips::try_fips_mode().is_ok()
);

/// Every provider compiled into this build.
pub fn compiled() -> Vec<&'static dyn CryptoProvider> {
    let mut providers: Vec<&'static dyn CryptoProvider> = Vec::new();
    #[cfg(feature = "ring")]
    providers.push(ring::provider());
    #[cfg(feature = "aws-lc-rs")]
    providers.push(aws_lc_rs::provider());
    #[cfg(feature = "fips")]
    providers.push(fips::provider());
    providers
}

#[cfg(test)]
mod tests {
    use super::*;
    use data_encoding::HEXLOWER;

    const ABC_SHA256: &str = "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad";
    const ABC_SHA512: &str = "ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a\
                              2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f";

    #[test]
    fn every_provider_matches_the_sha2_known_answers() {
        for provider in compiled() {
            for (alg, expected) in [
                (HashAlgorithm::Sha256, ABC_SHA256),
                (HashAlgorithm::Sha512, ABC_SHA512),
            ] {
                let mut context = provider.digest(&alg).unwrap();
                context.update(b"abc");
                assert_eq!(
                    HEXLOWER.encode(&context.finish()),
                    expected,
                    "{} {alg:?}",
                    provider.name()
                );
            }
        }
    }

    #[test]
    fn every_provider_verifies_every_providers_ed25519_signatures() {
        for signing in compiled() {
            let pkcs8 = signing.ed25519_generate_pkcs8().unwrap();
            let signer = signing.ed25519_from_pkcs8(&pkcs8).unwrap();
            let signature = signer.sign(b"message");
            for verifying in compiled() {
                let scheme = SignatureScheme::Ed25519;
                let key = signer.public_key();
                assert!(
                    verifying
                        .verify(&scheme, key, b"message", &signature)
                        .unwrap(),
                    "{} signature rejected by {}",
                    signing.name(),
                    verifying.name()
                );
                assert!(!verifying
                    .verify(&scheme, key, b"tampered", &signature)
                    .unwrap());
            }
        }
    }

    #[test]
    fn unknown_algorithms_are_errors() {
        for provider in compiled() {
            assert!(provider
                .digest(&HashAlgorithm::Unknown("md5".into()))
                .is_err());
            let scheme = SignatureScheme::Unknown("dsa".into());
            assert!(provider.verify(&scheme, b"", b"", b"").is_err());
        }
    }

    #[cfg(feature = "fips")]
    #[test]
    fn fips_provider_is_in_fips_mode() {
        assert!(fips::provider().fips());
    }

    #[cfg(feature = "ring")]
    #[test]
    fn ring_provider_is_not_fips() {
        assert!(!ring::provider().fips());
    }
}
