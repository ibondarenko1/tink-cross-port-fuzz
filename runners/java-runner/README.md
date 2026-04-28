# java-runner

Subprocess runner for tink-java JWK Set converter. Reads a JWK Set
from stdin, calls
`com.google.crypto.tink.jwt.JwkSetConverter.toPublicKeysetHandle`,
emits one JSON line describing the verdict.

## Build

```
mvn package
java -jar target/tink-cross-port-java-runner-0.1.0.jar < input.json
```

## Output schema

```json
{"verdict":"ACCEPT|REJECT_TINK|REJECT_OTHER",
 "error_class":"<java-exception-class-name>",
 "error_msg":"<truncated to 200 chars>",
 "keyset_shape":"<opaque>"}
```

## Verdict semantics

- **ACCEPT** — `toPublicKeysetHandle` returned a `KeysetHandle`.
- **REJECT_TINK** — public API raised the documented exceptions
  (`GeneralSecurityException`, `IOException`).
- **REJECT_OTHER** — public API raised an undocumented `RuntimeException`
  (e.g. NullPointerException, IllegalStateException). For the
  differential fuzzer this is treated as a contract-violation finding
  on the Java side.

## Current findings already surfaced by the runner

- `{}` and `{"foo":1}` → REJECT_OTHER (NullPointerException because
  `jsonKeyset.get("keys").getAsJsonArray()` on a missing field returns
  null and is dereferenced without an explicit check).
