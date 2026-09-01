# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What this is

`github.com/vocdoni/go-blindsecp256k1` — blind signatures over secp256k1, implementing the
Mala & Nezhadansari scheme ("New Blind Signature Schemes Based on the (Elliptic Curve)
Discrete Logarithm Problem"). Vocdoni-maintained fork of arnaucube/go-blindsecp256k1,
hardened for production. Pure Go (dcrd secp256k1 backend, no cgo). Wire-compatible with the
JS implementation at arnaucube/blindsecp256k1-js — **the byte-level test vectors in the
`*_test.go` files are the compatibility contract; never change them.**

## Commands

```sh
# tests (wasm is excluded — it only compiles with GOOS=js GOARCH=wasm)
go test $(go list ./... | grep -v /wasm)

# single test
go test -run TestFlow .

# benchmarks / fuzzers
go test -run=NONE -bench=. .
go test -run=NONE -fuzz=FuzzDecompressPoint -fuzztime=30s .   # one target at a time

# lint (CI uses golangci-lint v2 with .golangci.yml, skipping wasm)
golangci-lint run -c .golangci.yml .

# wasm compile check / build (pure Go, so this actually works at runtime)
GOOS=js GOARCH=wasm go build ./wasm     # or: cd wasm && ./build.sh
```

## Architecture

Single root package `blindsecp256k1`, backed by `github.com/decred/dcrd/dcrec/secp256k1/v4`
(Jacobian point ops, constant-time `ModNScalar` for secret scalars) and
`golang.org/x/crypto/sha3` (legacy Keccak-256, matching Ethereum).

The protocol is a four-step dance between Signer and User (equation↔code mapping in
`doc.go`): `NewRequestParameters` (signer: one-time k, R) → `Blind` (user) → `BlindSign`
(signer) → `Unblind` (user) → `Verify` (anyone).

File split:

- `blindsecp256k1.go` — scheme + `Point` arithmetic + compressed encodings. Public API keeps
  `big.Int`-based types; dcrd types stay internal (conversions via `scalarFromBigInt` /
  `toJacobian`).
- `parsers.go` — JSON marshalers and compressed-bytes constructors.
- `uncompressed.go` — legacy 64/96-byte little-endian encodings (`*Uncompressed` variants).
- `doc.go` — package doc: protocol math, security considerations, wire-format table.
- `security_test.go` — deterministic frozen vector, tamper/negative tests, properties.
- `fuzz_test.go`, `bench_test.go` — fuzz targets (never-panic + canonical round-trip) and
  benchmarks.
- `wasm/` — `js/wasm` browser wrapper (excluded from native tests and lint).

## Conventions and gotchas

- **Wire formats are frozen** (JS compat): compressed point = X **big-endian** + parity byte;
  everything else (S, uncompressed coords) is **little-endian**. Don't "fix" the asymmetry.
- All inputs are validated at the boundary: scalars must be in `[1, N)` (`validateScalar`),
  points must be on-curve and canonical (`isValid`). Parsers reject what `Verify` would
  reject.
- Secret-scalar math (d, k, a, b) must go through `ModNScalar`, never `big.Int` — that's the
  constant-time guarantee for `BlindSign`. Public-data math (e.g. in `Verify`) may use
  `big.Int`.
- The signer nonce `k` is one-time; API docs promise this loudly. Don't add any code path
  that persists or reuses it.
- Lint is strict (golangci-lint v2: gosec, mnd, lll@100, revive, staticcheck…). Byte-length
  constants of the wire encodings are allowlisted in `.golangci.yml` `ignored-numbers`.
- CI runs tests with `-race`, with `CGO_ENABLED=0`, and a wasm compile check — keep the
  package pure Go.
