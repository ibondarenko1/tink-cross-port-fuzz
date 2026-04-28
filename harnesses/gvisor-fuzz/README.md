# gvisor-fuzz: native Go fuzz harnesses for gvisor parsers

A small scaffold of `go test -fuzz` targets for parsers in
`google/gvisor`'s `pkg/tcpip/header`. **gvisor itself ships zero
`func Fuzz*` targets** — this repo plugs that gap so that the
parsers can be exercised by Go's built-in coverage-guided fuzzer
without a Bazel build environment.

## Why this works without Bazel

gvisor's main module needs Bazel to generate refcount / list /
sync templates. We bypass that by **vendoring just the leaf
parser source** (`tcp_parse.go` is a verbatim copy of
`ParseTCPOptions` from `pkg/tcpip/header/tcp.go` HEAD `478925c`).
The vendored copy has zero gvisor dependencies and compiles with
plain `go test -c`.

## Targets

- `header.FuzzParseTCPOptions` — TCP options parser, reachable from
  any TCP packet processed by gvisor netstack. Direct attacker-input
  surface; any panic is a remote DoS of the sandbox network stack.

## Run

```bash
cd harnesses/gvisor-fuzz
go test -c -o fuzz.test ./header
./fuzz.test -test.fuzz=FuzzParseTCPOptions -test.fuzztime=3600s
```

On Kali 2 (10 GB RAM, 6 cores) the harness sustains ~650k execs/sec
with 6 workers. After 30M+ executions on `ParseTCPOptions` HEAD
`478925c`, **no crashes were found** — consistent with the audit
finding that `ParseTCPOptions` is correctly length-bounded at every
step. The harness is shipped as a regression-prevention tool, not as
a known-bug reproducer.

## Adding new targets

1. Vendor the leaf parser source into `header/<file>.go` (omit gvisor
   imports; replace `seqnum.Value` → `SeqValue` etc. with stubs)
2. Add a `FuzzXxx` function in `header/fuzz_test.go`
3. Build and run

Candidates not yet vendored (PRs welcome):

- `IPv6OptionsExtHdrOptionsIterator.Next()` — iterator-style parser, higher bug density
- `header.ParseIPv4Options`
- `header.NDPNeighborSolicit` / `NeighborAdvert` accessors
- `header.IGMPv3` / `MLDv2` group record iterators

## Why this matters for portfolio

`gvisor` is in scope for Google OSS VRP at OT0. Any new fuzz harness
that finds a real panic in a netstack parser is a Tier-OT0 finding
with $$$ payout potential. The cost to add a target is ~30 lines of
vendoring + 5 lines of test boilerplate.
