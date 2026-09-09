> ⚠️ **This is a vendored fork of [theupdateframework/rust-tuf](https://github.com/theupdateframework/rust-tuf).**
>
> It is published under the name `libdd-tuf` to allow libdatadog to be released on
> crates.io without git dependencies. **Do not use this crate directly**

# rust-tuf

A Rust implementation of [The Update Framework (TUF)](https://theupdateframework.github.io/).

Full documentation is hosted at [docs.rs](https://docs.rs/libdd-tuf).

## Fork compatibility

The package is published as `libdd-tuf`, while the Rust library name remains `tuf`.
`tuf::interchange::Json` and `tuf::interchange::DataInterchange` remain aliases for the upstream
`tuf::pouf::Pouf1` type and `tuf::pouf::Pouf` trait.

`EphemeralRepository::get_target` provides synchronous access to in-memory targets and returns an
`Arc<[u8]>`. Returning owned shared bytes preserves upstream's concurrent repository updates
without exposing a lock guard or an unsound borrowed reference.

## Warning: Beta Software

This is under active development and may not suitable for production use. Further,
the API is unstable and you should be prepared to refactor on even patch releases.

## Contributing

Please make all pull requests to the `libdatadog-develop` branch.

### Bugs

Use the issue tracker for non-security bugs. Follow [SECURITY.md](./SECURITY.md) to report a
vulnerability privately.

## Legal

### License

This work is dual licensed under the MIT and Apache-2.0 licenses.
See [LICENSE-MIT](./LICENSE-MIT) and [LICENSE-APACHE](./LICENSE-APACHE) for details.
