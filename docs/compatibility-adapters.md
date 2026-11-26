# Compatibility adapters

The CLI sends one UTF-8 JSON object to an adapter and reads one object from stdout. The adapter returns its loaded Tink package version and runtime. A missing version, version mismatch, duplicate result ID or setup failure makes the affected measurements incomplete.

| Operation | Request | Result |
| --- | --- | --- |
| `publish` | `sets` maps names to public JWK Sets | Each set after import and export through Tink Python |
| `verify` | `checks` contains one entry per `id`, with `jwks`, `compact`, `issuer`, `now` in Unix seconds and optional `audience` | One `verified`, `rejected` or `error` outcome per ID |

The verifier imports each set, constructs a verification primitive and supplies the expected issuer, time and optional audience to the Tink validator. An expected rejection counts only when the library actually performed verification. The same signed RS256 fixture is checked with two expected audiences. [Fixtures](../tink_compat/data/vectors.json) · [RFC 7515 test signatures](https://www.rfc-editor.org/rfc/rfc7515.html#appendix-A)

## Contribute a version

1. Add the release and its upstream source to the [catalog](../tink_compat/data/catalog.json). Commit the Python requirements or the Go module and checksums for the selected version. Java uses the Tink Maven coordinate and the shared runner POM.
2. Update the candidate in the [reference profile](../tink_compat/data/profile.json). Keep previous entries so users can still select earlier releases.
3. Run `python -m pytest -q` and `python -m tink_compat check --out report`. Inspect the reported package versions, both mixed deployments and the Python controls. A working build alone does not establish interoperability.

A new scenario needs a public fixture, a fixed expected result, stable row IDs and an independent case in the release acceptance check. Include only public keys and signed test messages. [Release contract](../tools/release_contract.py)

## Release a version

The compatibility workflow builds a wheel from the sdist, compares it with the source and checks the complete case inventory against the measured report. The `release-assets` artifact contains the wheel, sdist, JSON, Markdown and SHA-256 manifest.

Bump the distribution version and the external Action tag in both the consumer example and the release smoke workflow. Push the matching tag and wait for the tagged compatibility build and the two independent consumer jobs. Use the assets from that tag's passing run to create the GitHub release. Publication checks the publicly downloaded wheel and deploys a checksum-verified page for each release. [Build workflow](../.github/workflows/compatibility.yml) · [Public installation checks](../.github/workflows/release-smoke.yml) · [Versioned results](https://ibondarenko1.github.io/tink-cross-port-fuzz/)
