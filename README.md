# Tink release compatibility

Check whether Go and Java services can still verify signed JWTs while a Python service updates Tink or rotates its public keys. The CLI runs real, pinned Tink packages and produces a JSON report for CI and a Markdown report for upgrade reviews.

[View the release results](https://ibondarenko1.github.io/tink-cross-port-fuzz/) · [Download v0.1.0](https://github.com/ibondarenko1/tink-cross-port-fuzz/releases/tag/v0.1.0) · [Copy the GitHub Actions workflow](https://github.com/ibondarenko1/tink-cross-port-fuzz/blob/v0.1.0/examples/consumer.yml)

This project started as a comparison of Tink's JWK parsers. That work confirmed a duplicate-field discrepancy fixed in Tink Python 1.15.0. [Upstream PR #76](https://github.com/tink-crypto/tink-py/pull/76) · [Tink Python release notes](https://github.com/tink-crypto/tink-py/releases/tag/v1.15.0)

## Run it in GitHub Actions

Copy [the complete workflow](https://github.com/ibondarenko1/tink-cross-port-fuzz/blob/v0.1.0/examples/consumer.yml) to `.github/workflows/tink-compat.yml` in your repository. The action installs the toolchains and runs the included upgrade profile on an Ubuntu runner. This is the step that produces the reports.

```yaml
- name: Check Tink compatibility
  id: tink
  uses: ibondarenko1/tink-cross-port-fuzz@v0.1.0
  with:
    out: compatibility-report
```

The outputs are `status`, `report-json` and `report-md`. The example uploads both files even when the check fails, so a reviewer can see which combination failed and why.

## Install the CLI

The release is tested on Linux x86_64 with Python 3.12, Go 1.25.4, JDK 21 and Maven 3.9. Install the wheel into a virtual environment. The first check downloads the pinned libraries and builds the Go and Java runners.

```bash
python3 -m venv .venv
. .venv/bin/activate
python -m pip install https://github.com/ibondarenko1/tink-cross-port-fuzz/releases/download/v0.1.0/tink_release_compat-0.1.0-py3-none-any.whl
tink-compat check --out compatibility-report
```

Open `compatibility-report/report.md` for the comparison or read `report.json` in CI. A second run against the same adapter cache can use `--offline`. To choose a cache explicitly, pass `--cache DIRECTORY` on both runs. The wheel, source distribution, measured reports and SHA-256 manifest are available together. [Release downloads](https://github.com/ibondarenko1/tink-cross-port-fuzz/releases/tag/v0.1.0)

## What the upgrade check measures

| Role | Baseline | Candidate |
| --- | --- | --- |
| Python publishes public JWK Sets | Tink 1.14.1 | Tink 1.15.0 |
| Go verifies compact signatures | Tink Go 2.4.0 | Tink Go 2.5.0 |
| Java verifies compact signatures | Tink Java 1.18.0 | Tink Java 1.18.0 |

Each Python publisher runs against both verifier configurations. Keeping Java fixed tests whether a service can stay on its current version while its Python peer upgrades. Reviewers can compare a mixed deployment with the fully upgraded one. The package versions are defined in the [release profile](https://github.com/ibondarenko1/tink-cross-port-fuzz/blob/v0.1.0/tink_compat/data/profile.json). Use `--profile PATH` to compare another combination of the bundled versions.

To add a package version or language, see the input and output contract for publishing keys and verifying messages. [Adapter contract](https://github.com/ibondarenko1/tink-cross-port-fuzz/blob/v0.1.0/docs/compatibility-adapters.md)

Each of the eight publisher/verifier combinations checks the published ES256 example from RFC 7515 and six outcomes from a rolling key change. Both Python versions also verify the RFC signature themselves. This gives 58 checks at fixed verification times. [RFC 7515, Appendix A.3](https://www.rfc-editor.org/rfc/rfc7515.html#appendix-A.3) · [Public fixtures](https://github.com/ibondarenko1/tink-cross-port-fuzz/blob/v0.1.0/tink_compat/data/vectors.json)

| Public keys deployed | Message signed by the old key | Message signed by the new key |
| --- | --- | --- |
| Old key | Verified | Rejected |
| Old and new keys | Verified | Verified |
| New key | Rejected | Verified |

The CLI returns **0 / PASS** when every required row matches, **1 / FAIL** when all required checks ran and an outcome differs, and **2 / INCOMPLETE** when a required result is missing. The JSON preserves individual failures even if another row is incomplete. Results cover these ES256 messages, public keys and package versions. They support a release decision alongside application-specific tests.

## Historical corpus

The original Python/Go comparison remains in the source checkout. Its summary now records which required port answered for each input. A missing runner gives an `INCOMPLETE` result. The signed release matrix above is the entry point for Java interoperability. [Historical harness](https://github.com/ibondarenko1/tink-cross-port-fuzz/blob/v0.1.0/harnesses/py/differential.py) · [Original corpus](https://github.com/ibondarenko1/tink-cross-port-fuzz/tree/v0.1.0/corpus_jwk/) · [Earlier project results](https://github.com/ibondarenko1/tink-cross-port-fuzz/blob/e6e0dc453692ecac6dde0a09c388efe0bbfbdef0/README.md)

Independent project maintained by Ievgen Bondarenko. [Apache 2.0 license](LICENSE)
