# serde_json cross-check

With E2EE, the gateway's receipt hashes the request after it has decrypted
it and serialized it again with Rust's serde_json (E2EE v2 §8). The SDK must
predict those bytes exactly, so `internal/serdejson` writes JSON as serde_json
does. This tool is serde_json itself, at the version and with the features of
the gateway build (1.0.149, `preserve_order`, `float_roundtrip`, zmij 1.0.21).

```sh
cargo build --release --manifest-path tools/serdecheck/Cargo.toml
SERDECHECK=tools/serdecheck/target/release/serdecheck go test ./internal/serdejson -run CrossCheck -v

# Record the corpus the unit tests check without Rust:
SERDECHECK=... SERDECHECK_WRITE=1 go test ./internal/serdejson -run CrossCheck
```

Last run 2026-10-26: 4,000,052 documents (2,000,000 random floats, each as
`encoding/json` and as the SDK writes it, plus integers, strings and objects)
agree byte for byte.
