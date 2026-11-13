# rust-tuf

A Rust implementation of [The Update Framework (TUF)](https://theupdateframework.github.io/).

Full documentation is hosted at [docs.rs](https://docs.rs/crate/tuf).

## Warning: Beta Software

This is under active development and may not suitable for production use. Further,
the API is unstable and you should be prepared to refactor on even patch releases.

## Crypto backends

Signature verification, signing, and hashing are provided by one of two crypto
libraries, selected with Cargo features:

| Feature | Backend | Notes |
|---|---|---|
| `ring` (default) | [*ring*](https://crates.io/crates/ring) | |
| `aws-lc-rs` | [aws-lc-rs](https://crates.io/crates/aws-lc-rs) | Uses the non-FIPS `aws-lc-sys` build of AWS-LC. |
| `fips` | aws-lc-rs 1.17.4 | Uses the certified AWS-LC-FIPS 3.x module (`aws-lc-fips-sys` 0.13), pinned through a git dependency. Does not pull in `aws-lc-sys`. |

The public API, the supported signature schemes (Ed25519, ECDSA P-256 with
SHA-256, and RSA-PSS behind `unstable_rsa`), and the supported hash algorithms
(SHA-256 and SHA-512) are the same on every backend.

To build without *ring*, disable default features and pick a backend. Re-add
`hyper` if you use `HttpRepository`:

```toml
[dependencies]
tuf = { version = "0.3.0-beta10", default-features = false, features = ["aws-lc-rs"] }
# or, for the FIPS module:
tuf = { version = "0.3.0-beta10", default-features = false, features = ["fips"] }
```

You can check that *ring* is not in the dependency graph with:

```sh
cargo tree -e normal --no-default-features --features aws-lc-rs -i ring
```

Building without any backend is a compile error. If several backends are enabled,
for example through Cargo feature unification, `fips` takes precedence over
`aws-lc-rs`, which takes precedence over `ring`; the others are compiled but unused.

Building with `fips` requires CMake, Go, and a C compiler; see the
[aws-lc-rs requirements](https://aws.github.io/aws-lc-rs/requirements/index.html).
aws-lc-rs 1.18 and later bind AWS-LC-FIPS 4.x, which AWS-LC lists as submitted to
NIST but not yet certified. `fips` therefore uses aws-lc-rs 1.17.4 from its git
tag, which binds AWS-LC-FIPS 3.x (CMVP certificates #5314 and #5298). Because a
git dependency is a separate package from the registry `aws-lc-rs`, this holds
even when other crates in your lockfile require aws-lc-rs 1.18 or later. Check
the module's security policy for the algorithms and operating environments it
covers.

## Contributing

Please make all pull requests to the `develop` branch.

### Bugs

This project has a **full disclosure** policy on security related errors. Please
treat these errors like all other bugs and file a public issue. Errors communicated
via other channels will be immediately made public.

## Legal

### License

This work is dual licensed under the MIT and Apache-2.0 licenses.
See [LICENSE-MIT](./LICENSE-MIT) and [LICENSE-APACHE](./LICENSE-APACHE) for details.
