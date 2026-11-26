# Compatibility adapter contract

The release CLI reads its signed fixtures from `tink_compat/data/vectors.json`. The ES256 signature and public coordinates in the first fixture come from RFC 7515 Appendix A.3. The two rotation messages are signed with different P-256 test keys and refer to an example issuer. Only the public JWKs and already-signed messages are distributed. [Fixtures](../tink_compat/data/vectors.json) · [RFC 7515](https://www.rfc-editor.org/rfc/rfc7515.html#appendix-A.3)

An adapter reads one UTF-8 JSON object on stdin, writes one JSON object on stdout and exits. A successful response includes the loaded Tink package `version` and a `runtime` string. The CLI compares the reported version with the profile. A version mismatch or setup failure makes the affected checks incomplete.

| Operation | Request | Response |
| --- | --- | --- |
| `publish` | `sets` maps the names `rfc`, `initial`, `overlap` and `retired` to public JWK Sets | `sets` contains each named public set after import and export through the publisher's Tink API |
| `verify` | `checks` is a list of objects containing `id`, `jwks`, `compact`, `issuer` and `now` (Unix seconds) | `results` contains one object per requested `id`, with `outcome` and an optional diagnostic `detail` |

A verifier imports the supplied public set, constructs the Tink verification primitive, sets the expected issuer and verification clock, and verifies the compact signature. It returns `verified` for success, `rejected` for a verification decision, and `error` if it could not perform verification. Setup errors cannot satisfy an expected rejection. Every requested ID must occur exactly once in the response.

To contribute a package version, add it to the supported versions, supply its dependency lock, and run the release profile with the existing signed fixtures. Include the JSON and Markdown reports when proposing a change to expected behavior. [Example profile](../tink_compat/data/profile.json) · [Published report](https://ibondarenko1.github.io/tink-cross-port-fuzz/report.json)

## Building the release downloads

The compatibility workflow builds a source distribution, builds the wheel from that distribution, and matches both to the measured fixtures and revision. Its `release-assets` artifact contains the wheel, source distribution, JSON, Markdown and `SHA256SUMS.txt`. For a release, take this artifact from the passing run on the version tag.

Publishing those files in GitHub Releases triggers two independent checks. One installs the wheel and runs the tagged action in fresh environments. The other verifies the report against the release checksums and tag, then updates the public results page. [Compatibility workflow](../.github/workflows/compatibility.yml) · [Distribution checks](../.github/workflows/release-smoke.yml)
