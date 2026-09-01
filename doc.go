// Package blindsecp256k1 implements the blind signature scheme over the
// secp256k1 curve described in "New Blind Signature Schemes Based on the
// (Elliptic Curve) Discrete Logarithm Problem" by Hamid Mala & Nafiseh
// Nezhadansari (https://doi.org/10.1109/ICCKE.2013.6682844).
//
// # Protocol
//
// The scheme involves two roles, the Signer (holding private key d with
// public key Q = dG) and the User. Mapping of the paper's equations to this
// package:
//
//	Signer:  k  random one-time secret, R = kG        NewRequestParameters
//	User:    a, b random blinding factors
//	         F  = aR + bG,  rx = F.x mod N
//	         m' = a⁻¹·rx·h(m) mod N                    Blind
//	Signer:  s' = d·m' + k mod N                       (*PrivateKey).BlindSign
//	User:    s  = a·s' + b mod N,  signature = (s, F)  Unblind
//	Anyone:  sG == F + rx·h(m)·Q                       Verify
//
// where h is the legacy Keccak-256 hash (as used by Ethereum). The Signer
// learns nothing about m (blindness): a and b perfectly randomize m' and
// (s, F) relative to the Signer's view (m', s', R).
//
// # Security considerations
//
//   - The Signer secret k is a one-time nonce. Signing two different blinded
//     messages with the same k reveals the private key:
//     d = (s'₁−s'₂)·(m'₁−m'₂)⁻¹ mod N. Generate a fresh (k, R) pair with
//     NewRequestParameters for every request, never persist or reuse k, and
//     discard it right after BlindSign.
//   - Schemes of this family are affected by ROS/Wagner-style attacks when a
//     large number of blind-signing sessions are open concurrently against
//     the same key: an attacker holding many unanswered R values can forge
//     one additional signature. Deployments should bound the number of
//     concurrently open sessions per key (issue R only when the request is
//     going to be answered promptly) and rotate keys where possible.
//   - Timing model: scalar arithmetic involving secrets (d, k, a, b) uses
//     dcrd's constant-time ModNScalar operations, so the Signer hot path
//     (BlindSign) is constant-time. Point multiplications and the modular
//     inversion inside Blind use variable-time algorithms (dcrd exposes only
//     variable-time point operations); User-side blinding secrets are
//     one-time values per session, which limits the value of what a timing
//     side channel could collect, but co-located attackers are not part of
//     the threat model this package defends against.
//   - Verify rejects non-canonical signatures (S outside [1, N)), ruling out
//     the trivial S+kN malleability. All parsers validate that decoded
//     points lie on the curve and that decoded scalars are canonical.
//
// # Wire formats
//
// All encodings are fixed-size and interoperable with the JS implementation
// at https://github.com/arnaucube/blindsecp256k1-js:
//
//	compressed Point (33 bytes):      X big-endian (32) ‖ parity of Y (1)
//	compressed Signature (65 bytes):  S little-endian (32) ‖ compressed F (33)
//	uncompressed Point (64 bytes):    X little-endian (32) ‖ Y little-endian (32)
//	uncompressed Signature (96 bytes): S little-endian (32) ‖ uncompressed F (64)
//
// Note the historical quirk kept for compatibility: inside the compressed
// point X is big-endian, while every other field is little-endian.
package blindsecp256k1
