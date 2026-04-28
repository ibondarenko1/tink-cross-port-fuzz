# gVisor sandbox escape hunt — nvproxy recon notes

**Goal:** find a memory-corruption / TOCTOU class bug in `pkg/sentry/devices/nvproxy/` that escalates from sentry-panic-DoS (the class we already shipped via #12925/#12927) to **sandbox escape into host kernel via NVIDIA driver passthrough**.

**Why nvproxy:** sentry untrusted ioctls are forwarded to the **host NVIDIA kernel driver** through `unix.RawSyscall(SYS_IOCTL, hostFD, …)`. NVIDIA has a long CVE history of driver bugs reachable via ioctl. If sentry's parameter-validation gap allows an attacker-controlled struct to reach a host-driver code path that NVIDIA hasn't sanitized, host kernel exploit becomes the chain.

**Repo HEAD:** `478925c` (google/gvisor as of 2026-04-28).

## Hot-zone files (recent churn + unsafe.Pointer density)

| File | LOC unsafe.Pointer | Recent commits 60d | Hypothesis |
|---|---|---|---|
| `frontend_unsafe.go` | 13 unsafe ptrs | yes | RawSyscall ioctl forwarding loop — most direct path |
| `frontend.go` | (size-validated path) | yes | Generic dispatch + simple ioctls; per-ioctl size check |
| `frontend_mmap_unsafe.go` | 1 ptr | yes | mmap of host fd into sentry; potentially ftw boundary |
| `nvproxy_unsafe.go` | 4 ptrs | yes | Driver version probe via direct syscall |
| `uvm_unsafe.go` | 2 ptrs | n/a | Unified memory ioctls; less audited |

## Specific hypotheses (each = one focused hunt)

### H1 — `frontendIoctlBytes` opaque-bytes forwarding

`frontend.go:322`: `frontendIoctlBytes(fi)` reads `fi.ioctlParamsSize` bytes from user, forwards to host with `frontendIoctlInvokeNoStatus(fi, &ioctlParams[0])`. The bytes are completely opaque to sentry; only ioctl `nr` is checked against an allowlist. If allowlist contains an ioctl number that the host NVIDIA driver expects to dereference an embedded pointer (and the pointer field is in attacker-controlled bytes), host driver follows the pointer → memory-corruption primitive.

**Verify:** trace allowlisted nrs in `version.go` to ones that historically (per NVIDIA CVE list) had embedded-pointer parameters.

### H2 — `rmapiParamsSizeCheck` overflow in *callers* (the function is correct)

`frontend.go:914-925` is well-formed (uint64 multiply, bounded by MAX_PARAMS_SIZE). But **callers** sometimes do *additional* multiplication after the gate. Audit every `rmapiParamsSizeCheck(...)` call site in `frontend.go` and `frontend_unsafe.go` for follow-up arithmetic that re-introduces the overflow gap.

Found 5 call sites — line 983, 1001, 1405 (frontend.go), 96, 171 (frontend_unsafe.go). Each needs a per-site audit for whether the buffer allocation downstream uses a *different* size value than the one checked.

### H3 — `ctrlClientSystemGetP2PCapsInitializeArray` GpuCount race

`frontend_unsafe.go:209-228`: allocates `numEntries := uint64(gpuCount) * uint64(gpuCount)`. The `gpuCount` is read from user-controlled `ctrlParams.GpuCount` in the caller. After `rmControlInvoke()` returns, `busPeerIDsBuf` is copied back to user. If `gpuCount` can be modified between the size check and the copy-back (TOCTOU on user memory? on shared sentry/guest memory?), the buffer size and copy size can disagree.

**Key question:** can guest user-space modify `ctrlParams.GpuCount` between the `CopyIn` at line 235 and the `CopyOut` at line 256? If yes → potential OOB read/write.

### H4 — driver version probe `unsafe.Sizeof(ioctlParams)` mismatch

`nvproxy_unsafe.go:48` and `:59` use `unsafe.Sizeof(ioctlParams)` as the param size in `frontendIoctlCmd`. The struct layout depends on Go compiler padding rules. If the host NVIDIA driver expects a specific C struct layout (no padding), and Go alignment introduces extra bytes, the host driver may read past the intended struct end into adjacent kernel memory. Cross-version (driver R515 vs R580 vs PQC variant) ABI mismatches are exactly this class.

### H5 — UVM ioctl audit (`uvm_unsafe.go`)

Unified memory ioctls forward `(*ui.cmd, ioctlParams)` — `ioctlParams` size and content unaudited beyond the type marshaling. UVM ioctls historically have higher CVE density than the frontend ioctls because they directly interact with VA management. **Best yield-per-effort target if H1-H4 dry up.**

## Approach for next session (3-7 day campaign)

1. **Dependency:** GPU-capable Linux box (memory: RTX machine 192.168.40.172). Need Kali 1 SSH back online; if not, use a cloud GPU instance.
2. **Build sentry with race detector + ASAN-equivalent for unsafe.Pointer paths** if practical (Go race detector should catch H3-class TOCTOU).
3. **Per-hypothesis hunt order:** H3 (highest expected yield, smallest code surface) → H1 (broadest, hardest to bound) → H2 (per-site audit, mechanical) → H5 (UVM) → H4 (cross-version ABI, requires multi-driver setup).
4. **Tooling:** the `tink-cross-port-fuzz` repo's atheris infra can be repurposed to drive nvproxy ioctl param-mutation fuzzing; not a 1-day port.

## Realistic outcome distribution (calibrate expectations)

- **70%** — no exploitable bug found in 7 days of hunt; produce a research-blog post on "what we audited and ruled out" instead. Still useful for portfolio.
- **25%** — one panic/DoS-class bug found (similar tier to #12925/#12927); CVE Medium, Tier-OT0 VRP eligible.
- **5%** — sandbox escape primitive found; Critical CVE; major portfolio milestone.

## Why this is the right hunt (vs. blind kernel fuzzing)

- Familiar territory — already shipped 2 systrap fixes and 1 nvproxy submission (#12921 currently open)
- Concrete attack-surface map (5 hypotheses above) — not "go find something in 4 million lines of code"
- Toolchain partially in place (tink-cross-port-fuzz infra)
- High-impact target — one find lifts the whole portfolio from "mid-level researcher" to "senior independent" tier

## Status

Recon notes only. No code changes. Saved as part of the differential-fuzzer repo because the same atheris/libfuzzer infrastructure can be repurposed for nvproxy fuzzing in the next milestone. To resume: clone `google/gvisor` fresh, walk through H3 first.
