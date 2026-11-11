# tink-cross-port-fuzz

A differential fuzzer for [Google Tink](https://github.com/tink-crypto) that feeds the **same input** to multiple language ports of the Tink crypto library and reports any **divergence** in acceptance, error class, or returned key shape.

## Why

Tink is implemented in C++, Go, Java, and Python with separate-but-parallel implementations of each crypto primitive. The four ports are expected to behave identically given the same input — but in practice they drift:

| Port | JWK Set with `{"keys": "string"}` | JWK Set RSA-PSS with only `dp` field |
| --- | --- | --- |
| tink-cc | rejects (`keys is not a list`) | rejects (`private keys cannot be converted`) |
| tink-go | rejects (`"keys" is not a list`) | rejects (`private key can't be converted`) |
| tink-java | **uncaught `IllegalStateException`** | **silently accepts as public key** |
| tink-py  | **uncaught `AttributeError`** | rejects |

Each row above is a real divergence in HEAD as of 2026-04-27. They were found by hand. This tool automates the search.

## Surface covered (current)

- `JwkSetConverter.toPublicKeysetHandle(jwk_set)` — JWK Set → Tink keyset (RFC 7517)
- `BinaryKeysetReader.read(bytes)` — protobuf Keyset deserialization (planned, milestone 2)

## How it works

For each input the harness asks every available runner what it does:

```
ACCEPT       — keyset constructed without error
REJECT_TINK  — port-recognized error (TinkError / GeneralSecurityException / etc.)
REJECT_OTHER — uncaught Python exception / Java unchecked exception (almost always a bug)
TIMEOUT      — runner exceeded budget
```

A `divergence` is when not all runners agree. Highest-priority report rows:

1. **`REJECT_OTHER` from any port** — uncaught exception is a contract violation; standalone bug
2. **`ACCEPT` from one port + `REJECT_TINK` from another** — semantic disagreement; potential cross-port confusion attack vector
3. **`ACCEPT` from all but one port** — outlier rejecting valid input or accepting invalid input

## Quick start

```bash
# install runners (Python is the only required port; others are optional)
pip install -r requirements.txt
# go install ./runners/go-runner   (optional)

# run on the bundled known-divergence corpus
python harnesses/py/differential.py corpus_jwk/

# fuzz with atheris (libFuzzer engine)
python harnesses/py/atheris_jwk.py corpus_jwk/
```

Each divergence is written to `reports/<sha1-of-input>.json` with the full per-port outcome.

## Status

**Milestone 1 — done 2026-04-28:** Python and Go runners on JWK Set converter.

End-to-end validated on Linux + Windows: 11/16 seed-corpus inputs flagged as cross-port divergences (`py:REJECT_OTHER` vs `go:REJECT_TINK`). Sample report row:

```
DIVERGENCE  01_alg_int.json   -> py:REJECT_OTHER (AttributeError)  / go:REJECT_TINK ("alg" is not a string)
DIVERGENCE  02_x_int.json     -> py:REJECT_OTHER (AttributeError)  / go:REJECT_TINK ("x" is not a string)
DIVERGENCE  06_kid_int.json   -> py:REJECT_OTHER (TypeError)        / go:REJECT_TINK ("kid" is not a string)
DIVERGENCE  11_keys_int.json  -> py:REJECT_OTHER (TypeError)        / go:REJECT_TINK ("keys" is not a list)
DIVERGENCE  14_keys_array_of_int.json -> py:REJECT_OTHER (AttributeError) / go:REJECT_TINK
agree       09_no_keys.json   -> py:REJECT_TINK / go:REJECT_TINK
agree       16_valid_es256_baseline.json -> py:ACCEPT / go:ACCEPT
```

The seed-corpus alone matches the bug class that was filed via Google OSS VRP (tracker `5332419769532416`, tink-java JwkSetConverter port-regression).

**Milestone 2 — planned:** Java runner via subprocess wrapper around `JwkSetConverter`. C++ runner via Bazel-built CLI.

**Milestone 3 — planned:** Add proto Keyset deserialization surface; structured corpus mining via libFuzzer + atheris.

## License

Apache 2.0. Tink itself is Apache 2.0; this harness is independent and only consumes the public APIs.

## Reporter

Ievgen Bondarenko ([@ibondarenko1](https://github.com/ibondarenko1)). Bug reports, PRs, and divergence corpora welcome.
