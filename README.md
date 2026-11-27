# Tink release compatibility

Can you upgrade a Go verifier before the Python service that publishes its keys? This Action reads both commits of a dependency-upgrade pull request, runs the released Tink packages against signed fixtures, and tells the reviewer which rollout orders passed. Java verifiers are supported too.

[Release results](https://ibondarenko1.github.io/tink-cross-port-fuzz/v0.2.0/) Â· [Install v0.2.0](https://github.com/ibondarenko1/tink-cross-port-fuzz/releases/tag/v0.2.0) Â· [Copy the workflow](examples/consumer.yml)

## Check a pull request

For a repository with an exact Python pin in `requirements.txt` and a Go module at its root, copy [consumer.yml](examples/consumer.yml) into `.github/workflows/tink-compat.yml`. The job needs `contents: read`. The Action checks out the base and head SHAs and posts the result in the job summary.

```yaml
- name: Check the Tink upgrade
  id: tink
  uses: ibondarenko1/tink-cross-port-fuzz@v0.2.0
  with:
    python-lock: requirements.txt
    go-module: .
```

For separate services in one repository, point the two inputs at their respective paths. The [example publisher and verifier](examples/services) use `examples/services/publisher/requirements.txt` and `examples/services/verifier`. The verifier has its own Go test for the message addressed to the billing service.

| Dependency input | How the checker uses it |
| --- | --- |
| `python-lock` | Reads the exact `tink==X.Y.Z` requirement. |
| `go-module` | Reads the selected version from the Go module graph in each checkout. The report records the declared requirement too. |
| `go-list` | Accepts a committed export of `go list -mod=readonly -m -json all` for the selected Go module. |
| `java-dependencies` | Reads a resolved Maven dependency list committed at the same path on each side. Generate it with `mvn dependency:list -DoutputFile=tink-dependencies.txt` in the Java service. |

When using a saved Go or Maven export, generate it in your build, then run `tink-compat stamp-export --root . --go-list go-list.json --go-module .` or `tink-compat stamp-export --root . --java-dependencies tink-dependencies.txt`. Commit the export and the generated `.inputs.json` together. The checker verifies their hashes against each checkout and records that the graph came from your build. A change to the recorded manifests requires a fresh export.

The matrix needs a Python publisher and at least one Go or Java verifier. For services in separate repositories, supply an explicit profile with the peer versions you intend to deploy. A missing manifest, unsupported Tink release or unavailable adapter produces `INCOMPLETE`. The full supported versions and release sources are in the [catalog](tink_compat/data/catalog.json).

## Read the result

The report compares the original deployment, the new publisher with old verifiers, old publisher with new verifiers, and the final deployment. It matches individual outcomes between the original and final deployments. The mixed combinations show which service can move first. For example, if only the new publisher with the old verifier fails, a verifier-first sequence can still pass the measured cases. The strict exit code remains 1 for that run.

| CLI exit | Meaning |
| --- | --- |
| `0` / PASS | Every required verification produced the expected outcome. |
| `1` / FAIL | All required measurements finished and at least one outcome differed. |
| `2` / INCOMPLETE | A required input, adapter or result was unavailable. |

The Markdown explains the decision. The JSON includes the raw checks, package versions, provenance and fixed-input hashes. The Action exposes `status`, `report-json` and `report-md`. The [example workflow](examples/consumer.yml) uploads the files on failure as well.

## Run locally

Install the [wheel](https://github.com/ibondarenko1/tink-cross-port-fuzz/releases/download/v0.2.0/tink_release_compat-0.2.0-py3-none-any.whl) in a Python 3.11+ environment. The release runs on Ubuntu x86-64 with Python 3.12, Go 1.25.11, JDK 21 and Maven 3.9. The project check prepares the adapters for the selected languages.

```bash
python -m pip install https://github.com/ibondarenko1/tink-cross-port-fuzz/releases/download/v0.2.0/tink_release_compat-0.2.0-py3-none-any.whl
tink-compat project --base ../service-before --head ../service-after \
  --python-lock requirements.txt --go-module . --out compatibility-report
```

To reproduce the release reference, use `tink-compat check --out report`, or specify `mode: sample` in the Action. For an explicit version pair, use `check --profile PATH` or the Action's `profile` input with that file checked out. After a successful run, `--offline` reuses prepared adapters. [Current profile](tink_compat/data/profile.json) Â· [Historical profile](tink_compat/data/profile-v0.1.json) Â· [v0.1.0 measurements](https://ibondarenko1.github.io/tink-cross-port-fuzz/v0.1.0/)

## What is measured

| Role | Reference baseline | Reference candidate |
| --- | --- | --- |
| Python publishes public JWK Sets | 1.15.0 | 1.16.1 |
| Go verifies messages | 2.5.0 | 2.9.0 |
| Java verifies messages | 1.18.0 | 1.24.0 |

Each publisher and verifier pair checks the ES256 and RS256 examples from RFC 7515. Six more cases follow a rotation from the old key, through the overlap, to the new key alone. Two audience checks use the same correctly signed RS256 message at a fixed time. The intended recipient accepts it and a different recipient rejects it. The Python verifier provides independent control rows. Only public keys and signed test messages are bundled. [RFC 7515](https://www.rfc-editor.org/rfc/rfc7515.html#appendix-A) Â· [Fixtures](tink_compat/data/vectors.json) Â· [Adapter contract](docs/compatibility-adapters.md)

## Project history

The original JWK comparison helped confirm a duplicate-field discrepancy fixed in Tink Python 1.15.0. The earlier corpus and its results are available in the source repository. [Upstream PR #76](https://github.com/tink-crypto/tink-py/pull/76) Â· [Original results](https://github.com/ibondarenko1/tink-cross-port-fuzz/blob/e6e0dc453692ecac6dde0a09c388efe0bbfbdef0/README.md) Â· [Corpus](corpus_jwk/)

Independent project maintained by Ievgen Bondarenko. [Apache 2.0 license](LICENSE)
