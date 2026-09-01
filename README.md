# go-blindsecp256k1 [![GoDoc](https://godoc.org/github.com/vocdoni/go-blindsecp256k1?status.svg)](https://godoc.org/github.com/vocdoni/go-blindsecp256k1) [![Go Report Card](https://goreportcard.com/badge/github.com/vocdoni/go-blindsecp256k1)](https://goreportcard.com/report/github.com/vocdoni/go-blindsecp256k1) [![Test](https://github.com/vocdoni/go-blindsecp256k1/workflows/Test/badge.svg)](https://github.com/vocdoni/go-blindsecp256k1/actions?query=workflow%3ATest)

Blind signatures over [secp256k1](https://en.bitcoin.it/wiki/Secp256k1), implementing
*"[New Blind Signature Schemes Based on the (Elliptic Curve) Discrete Logarithm
Problem](https://doi.org/10.1109/ICCKE.2013.6682844)"* by Hamid Mala & Nafiseh Nezhadansari.

Pure Go (no cgo), built on the constant-time scalar arithmetic of
[dcrd's secp256k1](https://github.com/decred/dcrd/tree/master/dcrec/secp256k1). Wire-compatible
with the JS implementation at
[arnaucube/blindsecp256k1-js](https://github.com/arnaucube/blindsecp256k1-js).

This is a fork of [arnaucube/go-blindsecp256k1](https://github.com/arnaucube/go-blindsecp256k1)
maintained by [Vocdoni](https://github.com/vocdoni), hardened for production use.

## Usage

```go
import (
	"math/big"

	blindsecp256k1 "github.com/vocdoni/go-blindsecp256k1"
)

// signer: create new signer key pair
sk, err := blindsecp256k1.NewPrivateKey()
signerPubK := sk.Public()

// signer: when user requests a new R parameter to blind a new msg,
// create a new one-time secret k with its public R. NEVER reuse k.
k, signerR, err := blindsecp256k1.NewRequestParameters()

// user: blind the msg using signer's R
msg := new(big.Int).SetBytes([]byte("test"))
msgBlinded, userSecretData, err := blindsecp256k1.Blind(msg, signerR)

// signer: sign the blinded message using the private key & secret k,
// then discard k
sBlind, err := sk.BlindSign(msgBlinded, k)

// user: unblind the blinded signature
sig, err := blindsecp256k1.Unblind(sBlind, userSecretData)

// anyone: verify the signature with the signer's public key
verified := blindsecp256k1.Verify(msg, sig, signerPubK)
```

## Wire formats

All encodings are fixed-size:

| Type | Size | Layout |
|---|---|---|
| compressed `Point` / `PublicKey` | 33 B | X big-endian (32) ‖ Y-parity byte (1) |
| compressed `Signature` | 65 B | S little-endian (32) ‖ compressed F (33) |
| uncompressed `Point` / `PublicKey` | 64 B | X little-endian (32) ‖ Y little-endian (32) |
| uncompressed `Signature` | 96 B | S little-endian (32) ‖ uncompressed F (64) |

`Compress`/`DecompressPoint` and `Bytes`/`New*FromBytes` handle the compressed forms;
`BytesUncompressed`/`New*FromBytesUncompressed` the uncompressed ones. JSON marshalers encode
coordinates as base-10 strings. Every parser validates its input: points must be on the curve
with canonical coordinates, and signature scalars must be in `[1, N)`.

## Security considerations

- **The signer secret `k` is a one-time nonce.** Signing twice with the same `k` reveals the
  private key. Generate a fresh `(k, R)` pair per request and discard `k` after `BlindSign`.
- **Bound concurrent signing sessions.** Blind signature schemes of this family are subject to
  ROS/Wagner-style attacks when many sessions are open in parallel against the same key.
- **Timing model.** Secret-scalar arithmetic is constant-time (dcrd `ModNScalar`); point
  multiplications and the blinding inversion are variable-time. See the
  [package documentation](https://pkg.go.dev/github.com/vocdoni/go-blindsecp256k1) for the
  full model and the equation↔code mapping.

## Development

```sh
go test ./...                       # test suite (root package)
go test -run=NONE -bench=. .        # benchmarks
go test -run=NONE -fuzz=FuzzDecompressPoint .   # fuzzers (one target at a time)
golangci-lint run -c .golangci.yml .
```

## WASM usage

The library is pure Go, so it compiles to WebAssembly. Wrappers for browser usage live in the
[wasm](wasm/) directory with an HTML & JS example.
