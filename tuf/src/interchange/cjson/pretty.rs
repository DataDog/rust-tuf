use serde::de::DeserializeOwned;
use serde::ser::Serialize;

use super::Json;
use crate::interchange::DataInterchange;
use crate::Result;

/// Pretty JSON data interchange.
///
/// This is identical to [Json] in all manners except for the `canonicalize` method. Instead of
/// writing the metadata in the canonical format, it first canonicalizes it, then pretty prints
/// the metadata.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct JsonPretty;

impl DataInterchange for JsonPretty {
    type RawData = serde_json::Value;

    /// ```
    /// # use tuf::interchange::{DataInterchange, JsonPretty};
    /// assert_eq!(JsonPretty::extension(), "json");
    /// ```
    fn extension() -> &'static str {
        Json::extension()
    }

    /// ```
    /// # use serde_json::json;
    /// # use tuf::interchange::{DataInterchange, JsonPretty};
    /// #
    /// let json = json!({
    ///     "o": {
    ///         "a": [1, 2, 3],
    ///         "s": "string",
    ///         "n": 123,
    ///         "t": true,
    ///         "f": false,
    ///         "0": null,
    ///     },
    /// });
    ///
    /// let bytes = JsonPretty::canonicalize(&json).unwrap();
    ///
    /// assert_eq!(&String::from_utf8(bytes).unwrap(), r#"{
    ///   "o": {
    ///     "0": null,
    ///     "a": [
    ///       1,
    ///       2,
    ///       3
    ///     ],
    ///     "f": false,
    ///     "n": 123,
    ///     "s": "string",
    ///     "t": true
    ///   }
    /// }"#);
    /// ```
    fn canonicalize(raw_data: &Self::RawData) -> Result<Vec<u8>> {
        // We explicitly normalise the `Value`'s key order before pretty-printing rather than
        // relying on `serde_json::Map`'s underlying type. Cargo features are unioned across the
        // workspace, so any consumer that pulls in `serde_json/preserve_order` (e.g. anything
        // depending on Vector) makes `Value::Object` an `IndexMap`, in which case
        // `to_vec_pretty` would emit keys in insertion order and break this method's contract.
        //
        // The earlier "canonicalize → from_slice → pretty" round-trip used to provide this
        // sorting indirectly, but that path also re-parsed the canonical bytes through
        // `serde_json::from_slice` — which fails on the literal control characters OLPC
        // canonical JSON emits inside string values (e.g. embedded newlines in PEM-encoded
        // ECDSA keys).
        Ok(serde_json::to_vec_pretty(&with_sorted_keys(raw_data))?)
    }

    /// ```
    /// # use serde_derive::Deserialize;
    /// # use serde_json::json;
    /// # use std::collections::HashMap;
    /// # use tuf::interchange::{DataInterchange, JsonPretty};
    /// #
    /// #[derive(Deserialize, Debug, PartialEq)]
    /// struct Thing {
    ///    foo: String,
    ///    bar: String,
    /// }
    ///
    /// let jsn = json!({"foo": "wat", "bar": "lol"});
    /// let thing = Thing { foo: "wat".into(), bar: "lol".into() };
    /// let de: Thing = JsonPretty::deserialize(&jsn).unwrap();
    /// assert_eq!(de, thing);
    /// ```
    fn deserialize<T>(raw_data: &Self::RawData) -> Result<T>
    where
        T: DeserializeOwned,
    {
        Json::deserialize(raw_data)
    }

    /// ```
    /// # use serde_derive::Serialize;
    /// # use serde_json::json;
    /// # use std::collections::HashMap;
    /// # use tuf::interchange::{DataInterchange, JsonPretty};
    /// #
    /// #[derive(Serialize)]
    /// struct Thing {
    ///    foo: String,
    ///    bar: String,
    /// }
    ///
    /// let jsn = json!({"foo": "wat", "bar": "lol"});
    /// let thing = Thing { foo: "wat".into(), bar: "lol".into() };
    /// let se: serde_json::Value = JsonPretty::serialize(&thing).unwrap();
    /// assert_eq!(se, jsn);
    /// ```
    fn serialize<T>(data: &T) -> Result<Self::RawData>
    where
        T: Serialize,
    {
        Json::serialize(data)
    }

    /// ```
    /// # use tuf::interchange::{DataInterchange, JsonPretty};
    /// # use std::collections::HashMap;
    /// let jsn: &[u8] = br#"{"foo": "bar", "baz": "quux"}"#;
    /// let _: HashMap<String, String> = JsonPretty::from_slice(&jsn).unwrap();
    /// ```
    fn from_slice<T>(slice: &[u8]) -> Result<T>
    where
        T: DeserializeOwned,
    {
        Json::from_slice(slice)
    }
}

/// Recursively rebuild a `serde_json::Value` so every object's keys are emitted in sorted order
/// when re-serialized, regardless of whether `serde_json` was built with the `preserve_order`
/// feature (which swaps `Map`'s underlying type from `BTreeMap` to `IndexMap`).
///
/// When `preserve_order` is enabled, `Map::insert` preserves insertion order, so inserting in
/// sorted order produces a map that iterates in sorted order. When it is not enabled, `Map`
/// uses `BTreeMap`, which always iterates in sorted order; the explicit sort here is then a
/// no-op on the iteration order but still produces an equivalent value.
fn with_sorted_keys(value: &serde_json::Value) -> serde_json::Value {
    match value {
        serde_json::Value::Object(map) => {
            let mut entries: Vec<(&String, &serde_json::Value)> = map.iter().collect();
            entries.sort_by(|a, b| a.0.cmp(b.0));
            let mut sorted = serde_json::Map::with_capacity(entries.len());
            for (k, v) in entries {
                sorted.insert(k.clone(), with_sorted_keys(v));
            }
            serde_json::Value::Object(sorted)
        }
        serde_json::Value::Array(arr) => {
            serde_json::Value::Array(arr.iter().map(with_sorted_keys).collect())
        }
        other => other.clone(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    /// Regression test: prior to skipping the canonical-bytes round-trip, calling
    /// `JsonPretty::canonicalize` on any value containing a string with control characters (an
    /// embedded newline, tab, etc.) failed with a "control character while parsing a string"
    /// error from `serde_json::from_slice`, because OLPC canonical JSON emits those bytes
    /// literally and that form is not strict JSON.
    #[test]
    fn canonicalize_handles_strings_with_control_characters() {
        let value = json!({
            "key_with_newlines": "-----BEGIN PUBLIC KEY-----\nABC\n-----END PUBLIC KEY-----\n",
            "key_with_tab": "a\tb",
        });
        let bytes = JsonPretty::canonicalize(&value).expect("must not fail on control chars");

        // Round-trips back to the same value.
        let reparsed: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(reparsed, value);

        // Pretty output sorts top-level keys (alphabetical: `key_with_newlines`, `key_with_tab`).
        let s = std::str::from_utf8(&bytes).unwrap();
        assert!(s.find("key_with_newlines").unwrap() < s.find("key_with_tab").unwrap());
    }

    /// `JsonPretty::canonicalize` must emit object keys in sorted order regardless of whether
    /// `serde_json` was built with `preserve_order` (which swaps `Map`'s underlying type from
    /// `BTreeMap` to `IndexMap`). The test build for this crate enables `preserve_order` via a
    /// `[dev-dependencies]` declaration in `tuf/Cargo.toml`, so this assertion runs against the
    /// `IndexMap` code path on every `cargo test` invocation — the same map type any consumer
    /// that depends on Vector (or another `preserve_order` consumer) sees in production.
    /// Inserting keys in reverse-alphabetical order ensures that any code path which simply
    /// iterates the map without sorting would emit them in the wrong order.
    #[test]
    fn canonicalize_sorts_keys_recursively_against_insertion_order() {
        let mut top = serde_json::Map::new();
        // Insert in reverse-alphabetical order; under preserve_order this is the iteration
        // order, under BTreeMap it gets sorted.
        let mut nested = serde_json::Map::new();
        nested.insert("z_inner".to_string(), json!(1));
        nested.insert("a_inner".to_string(), json!(2));
        top.insert("z_top".to_string(), serde_json::Value::Object(nested));
        top.insert("a_top".to_string(), json!("first alphabetically"));

        let value = serde_json::Value::Object(top);
        let bytes = JsonPretty::canonicalize(&value).unwrap();
        let pretty = std::str::from_utf8(&bytes).unwrap();

        // Top-level: a_top before z_top.
        let a_top = pretty.find("a_top").unwrap();
        let z_top = pretty.find("z_top").unwrap();
        assert!(a_top < z_top, "top-level keys must sort: {pretty}");

        // Nested object: a_inner before z_inner.
        let a_inner = pretty.find("a_inner").unwrap();
        let z_inner = pretty.find("z_inner").unwrap();
        assert!(a_inner < z_inner, "nested keys must sort: {pretty}");
    }
}
