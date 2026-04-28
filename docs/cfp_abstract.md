# Same crypto, different bugs: cross-port consistency drift in google/tink

## Abstract (250 words — fits OffensiveCon / Insomni'hack / NorthSec / ZeroNights submission cap)

Google Tink ships the same JWT/JOSE/AEAD/MAC API in four parallel implementations: tink-cc (C++), tink-go (Go), tink-java (Java), and tink-py (Python). The four ports are intended to be drop-in interchangeable — a JWK Set fetched from an issuer should produce the same Tink keyset regardless of which port the verifier runs on, and a malformed JWK should be rejected with a documented error class everywhere.

In practice the four ports drift. This talk presents `tink-cross-port-fuzz`, an open-source differential fuzzer that feeds identical JWK Set / Keyset proto inputs to all four ports and reports any divergence in acceptance, error class, or key shape. We walk through real divergences shipped in HEAD as of 2026-04-27:

- **CWE-755** — tink-java's `JwkSetConverter.toPublicKeysetHandle` raises uncaught `NullPointerException` / `IllegalStateException` on malformed top-level `keys` field, while tink-cc and tink-go reject cleanly with documented error classes. Result: unauthenticated DoS + stack-trace info-leak in any JWT verifier that fetches an external JWKS.
- **CWE-674** — bumble.sdp's recursive parser crashed on attacker-controlled SDP responses; the same depth-cap pattern was missing in three different tink contexts.
- **Silent integer truncation** — tink-go's RSA public-exponent path drops the high bits of `e` in six proto/JWK deserialization sites, while a sibling path (`internal/signature/rsa.go:69-72`) implements the canonical `IsInt64()` guard.

We discuss why these classes survive code review (Java/Go strong typing creates a false sense of security; cross-port consistency tests run only at the API surface), how to weaponize differential fuzzing for OAuth/JWT-relevant bug classes, and what defenders can pull into their own pipelines today.

The tool, the corpora, the reproducers, and the CVE links are public.

## Speaker bio (75 words)

Ievgen Bondarenko is an independent security researcher focused on cryptographic-API consistency bugs and Bluetooth-stack robustness. In 2026 he reported and got merged DoS / parser bugs in google/bumble (Bluetooth stack), google/gvisor (sandbox), google/osv-scanner, and google/tink, with multiple CVEs assigned via MITRE and Google OSS VRP. He authors the `tink-cross-port-fuzz` differential harness used in this talk.

## Outline (40 minutes)

1. **3 min — Why differential fuzzing for cross-port crypto APIs**
   - The "same API, four implementations" promise
   - Why API-surface tests don't catch error-class drift
   - Threat model: OAuth / OIDC / federation / JWT verifier on hostile JWKS

2. **8 min — Live demo: tink-cross-port-fuzz**
   - 16-file seed corpus, four runners (tink-cc / tink-go / tink-java / tink-py)
   - Python orchestrator → divergence buckets (UNCAUGHT_EXCEPTION / ACCEPT_VS_REJECT / AGREE)
   - Reading a divergence report

3. **10 min — Walkthrough of real divergences in HEAD**
   - Java's missing `keys` array null/type check (CWE-755)
   - Java's PSS converter `dq` vs `dp` typo (asymmetric private-key gate)
   - Go's RSA exponent `Int64()` truncation across 6 sites
   - Python's `cast(str, ...)` is a type-hint, not a runtime check (8 inputs, 8 distinct exception classes)

4. **8 min — Why these survive review**
   - Strong-typed languages and the false sense of security
   - Test fixtures cover the API surface, not the error surface
   - "Other ports do it differently" → sibling-pattern citation as reviewer leverage

5. **6 min — Building your own cross-port harness**
   - Generalizing beyond tink: any multi-port crypto / parser / serializer library
   - Subprocess vs in-process runners (memory budget vs latency)
   - Atheris + libFuzzer corpus seeding from differentials

6. **3 min — Disclosure timeline + CVE/VRP outcomes**
   - PRs merged in google/tink, google/bumble, google/gvisor
   - CVE IDs assigned (3 via MITRE, additional via Google OSS VRP)
   - What didn't get a CVE and why (Tier scoping, "DoS-only" policy)

7. **2 min — Q&A pointer + repo link**

## Target conferences and CFP windows

| Conference | Typical CFP open | Deadline | Fit |
|---|---|---|---|
| **OffensiveCon 2027 (Berlin)** | July 2026 | Oct 2026 | Excellent — strong technical talk culture, similar past talks |
| **NorthSec 2027 (Montreal)** | Nov 2026 | Jan 2027 | Excellent — Canadian, defensive+offensive balance |
| **Insomni'hack 2027 (Geneva)** | Sep 2026 | Dec 2026 | Excellent — Europe, strong fuzzing track record |
| **ZeroNights 2026/27** | Variable | Variable | Good — historical interest in Russian-speaker submissions |
| **DEF CON 34 (2026)** | Feb 2026 | Apr 2026 | Probably just past — check appsec or AI villages |
| **Black Hat USA 2026** | Jan 2026 | Apr 2026 | Probably past — try Asia / EU 2026 instead |
| **SAS by Kaspersky 2027** | Aug 2026 | Oct 2026 | Good — offensive-research focused |
| **EkoParty 2026 (BA)** | Aug 2026 | Sep 2026 | Strong fit — Latin American crypto / fuzzing community |

## Submission tracker

- [ ] OffensiveCon 2027 — submit when CFP opens (~Jul 2026)
- [ ] NorthSec 2027 — submit ~Nov-Dec 2026
- [ ] Insomni'hack 2027 — submit ~Oct-Nov 2026
- [ ] EkoParty 2026 — try if CFP still open

Submit the same abstract to multiple CFPs (no exclusivity for technical talks under typical conference rules; check each).

## Pre-talk dependencies (tracked here so we don't lose track)

- [ ] M2 of `tink-cross-port-fuzz` — Java + C++ runners shipped
- [ ] At least 3 CVE IDs assigned (MITRE for bumble + Google OSS VRP for tink-java tracker `5332419769532416`)
- [ ] At least one PR merged from the tool's findings (currently: tink-go-gcpkms#21 in review)
- [ ] Tag `v0.1.0` release on the repo when M2 lands
