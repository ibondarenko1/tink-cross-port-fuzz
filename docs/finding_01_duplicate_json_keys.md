# Finding 01: tink-py JwkSetConverter accepts duplicate JSON keys (cross-impl confusion class)

**Status:** confirmed on tink-py and tink-go HEAD as of 2026-04-28. NOT yet submitted upstream.
**Found by:** this repo's differential harness + atheris JWK corpus growth (~8 minutes runtime).
**Class:** cross-port semantic divergence; auth-confusion family (JOSE).

## Bug

`tink.jwt._jwk_set_converter.to_public_keyset_handle(jwk_set)` parses the JWK Set with Python's stdlib `json.loads()`, which silently accepts duplicate JSON object keys per CPython behavior (last-value-wins). All other Tink ports use protobuf JSON parsers that strict-reject duplicate keys per RFC 8259 best practice.

## Reproduction

Four divergent inputs are checked into `corpus_jwk/`:

| File | Input fragment | tink-py | tink-go |
|---|---|---|---|
| `17_dup_alg_none_first.json` | `{"alg":"none","alg":"PS256","kty":"RSA","n":"AAAA","e":"AAAA"}` | ACCEPT (effective alg=PS256) | REJECT: `proto: (line 1:24): duplicate map key "alg"` |
| `18_dup_kid.json` | `{...,"kid":"victim_kid","kid":"attacker_kid"}` | ACCEPT (effective kid=attacker_kid) | REJECT: `duplicate map key "kid"` |
| `19_dup_kty_EC_first_RSA_last.json` | `{"kty":"EC","kty":"RSA",...}` | ACCEPT (effective kty=RSA) | REJECT: `duplicate map key "kty"` |
| atheris-grown corpus (`reports/f78a5cffb53b4d1a.json` etc.) | malformed combinations | ACCEPT vs REJECT | per-tool difference logged |

Run the harness on this repo to reproduce:

```bash
python harnesses/py/differential.py corpus_jwk/
# Look for entries with category=ACCEPT_VS_REJECT in reports/
```

## Threat model

A real-world deployment pattern that exposes this:

1. Multi-tenant identity provider hosts a JWKS endpoint
2. Service A (tink-go) pulls + validates the JWK Set as well-formed input
3. Service B (tink-py) pulls + parses the same bytes for verification
4. Attacker submits a JWK Set with duplicated `alg` / `kid` / `kty` / `n`
5. Service A rejects (correct behavior)
6. Service B accepts; effective field value = last-occurrence-in-JSON
7. Whoever the attacker put in the SECOND occurrence becomes the operative attribute used by Service B

Concrete attack: signing-key migration / publication. Issuer publishes a JWK Set that tink-go pre-validators accept (because the duplicate is gone after a "scrub" step) or reject (and the operator then "fixes" it manually for tink-py). Either way, what tink-py believes about `kid`, `alg`, `n` differs from what tink-go would have.

This is the SAME class as historic CVE-2022-21449 (Java ECDSA cross-impl), CVE-2018-0114 (multi-impl JOSE), and the cross-library trust bugs in MSAL.js / MSAL.NET (where one library's parser accepts what another rejects).

## CVSS estimate

`AV:N/AC:H/PR:N/UI:N/S:C/C:L/I:H/A:N` ≈ **6.8 Medium**, leaning High in deployments where tink-py is the verifier and a strict-parser like tink-go is used as the publication / validation pre-filter.

## Patch sketch (proposed for tink-py)

```python
# in tink/jwt/_jwk_set_converter.py
def _reject_dup_keys(pairs):
    seen = set()
    for k, _ in pairs:
        if k in seen:
            raise tink.TinkError(f"JWK Set has duplicate key {k!r}")
        seen.add(k)
    return dict(pairs)

def to_public_keyset_handle(jwk_set: str) -> tink.KeysetHandle:
    try:
        keys_dict = json.loads(jwk_set, object_pairs_hook=_reject_dup_keys)
    except (json.JSONDecodeError, tink.TinkError) as e:
        raise tink.TinkError(f"error parsing JWK set: {e}")
    # ... rest unchanged
```

This brings tink-py to documented parity with tink-go and tink-cc protobuf-strict JSON parsing.

## Disclosure plan

1. Open PR to `tink-crypto/tink-py` with the patch sketch above + test cases for each duplicated field
2. Wait for merge
3. Submit Google OSS VRP report referencing merged PR + this finding doc + the four reproducer files in `corpus_jwk/`
4. tink-py is OT2 in OSS VRP scope, so the merged-patch path is required (per OSS VRP rules)
