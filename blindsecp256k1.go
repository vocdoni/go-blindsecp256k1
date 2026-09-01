// Package blindsecp256k1 implements the Blind signature scheme explained at
// "New Blind Signature Schemes Based on the (Elliptic Curve) Discrete
// Logarithm Problem", by Hamid Mala & Nafiseh Nezhadansari
// https://sci-hub.st/10.1109/ICCKE.2013.6682844
//
// LICENSE can be found at https://github.com/vocdoni/go-blindsecp256k1/blob/master/LICENSE
package blindsecp256k1

import (
	"bytes"
	"fmt"
	"math/big"

	secp256k1 "github.com/decred/dcrd/dcrec/secp256k1/v4"
	"golang.org/x/crypto/sha3"
)

var (
	zero = big.NewInt(0)

	// B (from y^2 = x^3 + B)
	B = big.NewInt(7) //nolint:mnd // the secp256k1 curve constant b=7

	// P represents the secp256k1 finite field
	P = secp256k1.Params().P

	// G represents the base point of secp256k1
	G = &Point{
		X: secp256k1.Params().Gx,
		Y: secp256k1.Params().Gy,
	}

	// N represents the order of G of secp256k1
	N = secp256k1.Params().N
)

// keccak256 returns the legacy Keccak-256 hash (as used by Ethereum) of b.
func keccak256(b []byte) []byte {
	h := sha3.NewLegacyKeccak256()
	h.Write(b)
	return h.Sum(nil)
}

// scalarFromBigInt converts v into a constant-time ModNScalar, reducing it
// modulo N (matching big.Int mod-N arithmetic for any input, negatives
// included).
func scalarFromBigInt(v *big.Int) *secp256k1.ModNScalar {
	var buf [32]byte
	new(big.Int).Mod(v, N).FillBytes(buf[:])
	s := new(secp256k1.ModNScalar)
	s.SetBytes(&buf)
	return s
}

// scalarToBigInt converts a ModNScalar back to a *big.Int.
func scalarToBigInt(s *secp256k1.ModNScalar) *big.Int {
	b := s.Bytes()
	return new(big.Int).SetBytes(b[:])
}

// Point represents a point on the secp256k1 curve
type Point struct {
	X *big.Int
	Y *big.Int
}

// toJacobian converts p to a Jacobian point (Z=1), reducing the coordinates
// mod P. The affine point (0, 0) keeps representing the point at infinity,
// which is the convention the dcrd group operations use as well.
func (p *Point) toJacobian(result *secp256k1.JacobianPoint) {
	var x, y, z secp256k1.FieldVal
	x.SetByteSlice(new(big.Int).Mod(p.X, P).Bytes())
	y.SetByteSlice(new(big.Int).Mod(p.Y, P).Bytes())
	z.SetInt(1)
	*result = secp256k1.MakeJacobianPoint(&x, &y, &z)
}

// jacobianToPoint converts j back to an affine Point. The point at infinity
// maps to (0, 0).
func jacobianToPoint(j *secp256k1.JacobianPoint) *Point {
	j.ToAffine()
	return &Point{
		X: new(big.Int).SetBytes(j.X.Bytes()[:]),
		Y: new(big.Int).SetBytes(j.Y.Bytes()[:]),
	}
}

// Add performs the Point addition
func (p *Point) Add(q *Point) *Point {
	var jp, jq, jr secp256k1.JacobianPoint
	p.toJacobian(&jp)
	q.toJacobian(&jq)
	secp256k1.AddNonConst(&jp, &jq, &jr)
	return jacobianToPoint(&jr)
}

// Mul performs the Point scalar multiplication. The scalar is interpreted
// mod N.
func (p *Point) Mul(scalar *big.Int) *Point {
	k := scalarFromBigInt(scalar)
	var jr secp256k1.JacobianPoint
	if p.X.Cmp(G.X) == 0 && p.Y.Cmp(G.Y) == 0 {
		// base-point multiplication uses the precomputed table
		secp256k1.ScalarBaseMultNonConst(k, &jr)
	} else {
		var jp secp256k1.JacobianPoint
		p.toJacobian(&jp)
		secp256k1.ScalarMultNonConst(k, &jp, &jr)
	}
	return jacobianToPoint(&jr)
}

// isOnCurve reports whether p satisfies y^2 = x^3 + B with both coordinates
// in [0, P).
func (p *Point) isOnCurve() bool {
	if p.X.Sign() < 0 || p.Y.Sign() < 0 || p.X.Cmp(P) >= 0 || p.Y.Cmp(P) >= 0 {
		return false
	}
	y2 := new(big.Int).Mod(new(big.Int).Mul(p.Y, p.Y), P)
	x3 := new(big.Int).Mul(new(big.Int).Mul(p.X, p.X), p.X)
	x3b := new(big.Int).Mod(x3.Add(x3, B), P)
	return y2.Cmp(x3b) == 0
}

func (p *Point) isValid() error {
	if p == nil || p.X == nil || p.Y == nil {
		return fmt.Errorf("point is nil")
	}
	if !p.isOnCurve() {
		return fmt.Errorf("point is not on secp256k1")
	}

	if bytes.Equal(p.X.Bytes(), zero.Bytes()) &&
		bytes.Equal(p.Y.Bytes(), zero.Bytes()) {
		return fmt.Errorf("point (%s, %s) can not be (0, 0)",
			p.X.String(), p.Y.String())
	}
	return nil
}

// Compress packs a Point to a byte array of 33 bytes: the X coordinate as
// 32 big-endian bytes followed by a parity byte (1 if Y is odd, 0 if even).
func (p *Point) Compress() [33]byte {
	xBytes := p.X.Bytes()
	odd := byte(0)
	if isOdd(p.Y) {
		odd = byte(1)
	}
	var b [33]byte
	copy(b[32-len(xBytes):32], xBytes)
	b[32] = odd
	return b
}

func isOdd(b *big.Int) bool {
	return b.Bit(0) != 0
}

// DecompressPoint unpacks a Point from the given byte array of 33 bytes:
// 32 big-endian bytes for the X coordinate followed by a parity byte.
func DecompressPoint(b [33]byte) (*Point, error) {
	if b[32] > 1 {
		return nil, fmt.Errorf("invalid parity byte %d, expected 0 or 1", b[32])
	}
	odd := b[32] == 1

	var x secp256k1.FieldVal
	if overflow := x.SetByteSlice(b[:32]); overflow {
		return nil, fmt.Errorf("x coordinate >= field prime P")
	}

	// y = sqrt(x^3 + B) with the requested parity; fails if x is not the
	// abscissa of a curve point
	var y secp256k1.FieldVal
	if !secp256k1.DecompressY(&x, odd, &y) {
		return nil, fmt.Errorf("invalid point: x is not on the curve")
	}
	y.Normalize()

	p := &Point{
		X: new(big.Int).SetBytes(x.Bytes()[:]),
		Y: new(big.Int).SetBytes(y.Bytes()[:]),
	}
	return p, p.isValid()
}

// PrivateKey represents the signer's private key
type PrivateKey big.Int

// PublicKey represents the signer's public key
type PublicKey Point

// newRand returns a cryptographically secure random scalar in [1, N-1].
func newRand() (*big.Int, error) {
	k, err := secp256k1.GeneratePrivateKey()
	if err != nil {
		return nil, err
	}
	return new(big.Int).SetBytes(k.Serialize()), nil
}

// NewPrivateKey returns a new random private key
func NewPrivateKey() (*PrivateKey, error) {
	k, err := newRand()
	if err != nil {
		return nil, err
	}
	sk := PrivateKey(*k)
	return &sk, nil
}

// BigInt returns a *big.Int representation of the PrivateKey
func (sk *PrivateKey) BigInt() *big.Int {
	return (*big.Int)(sk)
}

// Public returns the PublicKey from the PrivateKey
func (sk *PrivateKey) Public() *PublicKey {
	q := G.Mul(sk.BigInt())
	pk := PublicKey(*q)
	return &pk
}

// Point returns a *Point representation of the PublicKey
func (pk *PublicKey) Point() *Point {
	return (*Point)(pk)
}

// NewRequestParameters returns a new random k (secret) & R (public) parameters
func NewRequestParameters() (*big.Int, *Point, error) {
	k, err := newRand()
	if err != nil {
		return nil, nil, err
	}
	// k, R = kG
	return k, G.Mul(k), nil
}

// validateScalar checks that v is a canonical non-zero scalar for the group,
// i.e. in the range [1, N).
func validateScalar(v *big.Int) error {
	if v == nil {
		return fmt.Errorf("nil value")
	}
	if v.Sign() <= 0 {
		return fmt.Errorf("value must be positive and non-zero")
	}
	if v.Cmp(N) >= 0 {
		return fmt.Errorf("value must be inside the finite field (< N)")
	}
	return nil
}

// BlindSign performs the blind signature on the given mBlinded using the
// PrivateKey and the secret k values.
func (sk *PrivateKey) BlindSign(mBlinded *big.Int, k *big.Int) (*big.Int, error) {
	if err := validateScalar(mBlinded); err != nil {
		return nil, fmt.Errorf("mBlinded error: %s", err)
	}
	if err := validateScalar(k); err != nil {
		return nil, fmt.Errorf("k error: %s", err)
	}
	if sk == nil {
		return nil, fmt.Errorf("private key error: nil value")
	}
	if err := validateScalar(sk.BigInt()); err != nil {
		return nil, fmt.Errorf("private key error: %s", err)
	}

	// s' = dm' + k, computed with constant-time scalar arithmetic as d and
	// k are secret
	d := scalarFromBigInt(sk.BigInt())
	m := scalarFromBigInt(mBlinded)
	kS := scalarFromBigInt(k)
	sBlind := new(secp256k1.ModNScalar).Mul2(d, m).Add(kS)
	return scalarToBigInt(sBlind), nil
}

// UserSecretData contains the secret values from the User (a, b) and the
// public F
type UserSecretData struct {
	A *big.Int
	B *big.Int

	F *Point // public (in the paper is named R)
}

// maxBlindAttempts bounds the resampling loop in Blind. Each retry only
// happens when the random blinding factors produce a degenerate F (an
// astronomically unlikely event with honest inputs), so hitting the bound
// means something is seriously wrong with the inputs or the RNG.
const maxBlindAttempts = 16

// Blind performs the blinding operation on m using signerR parameter
func Blind(m *big.Int, signerR *Point) (*big.Int, *UserSecretData, error) {
	if m == nil {
		return nil, nil, fmt.Errorf("m can not be nil")
	}
	if err := signerR.isValid(); err != nil {
		return nil, nil, fmt.Errorf("signerR %s", err)
	}

	h := new(big.Int).SetBytes(keccak256(m.Bytes()))
	if new(big.Int).Mod(h, N).Sign() == 0 {
		// h(m) ≡ 0 (mod N) would force mBlinded = 0 for any blinding
		// factors; no valid signature can be produced for such m
		return nil, nil, fmt.Errorf("message hash maps to the zero scalar")
	}

	for attempt := 0; attempt < maxBlindAttempts; attempt++ {
		var err error
		u := &UserSecretData{}
		u.A, err = newRand()
		if err != nil {
			return nil, nil, err
		}
		u.B, err = newRand()
		if err != nil {
			return nil, nil, err
		}

		// (R) F = aR' + bG
		aR := signerR.Mul(u.A)
		bG := G.Mul(u.B)
		u.F = aR.Add(bG)

		rx := new(big.Int).Mod(u.F.X, N)
		if u.F.isValid() != nil || rx.Sign() == 0 {
			// F degenerate (point at infinity) or rx ≡ 0 (mod N):
			// resample the blinding factors
			continue
		}

		// m' = a^-1 rx h(m), computed with scalar arithmetic as a is
		// secret (the modular inversion itself is not constant-time;
		// see the package documentation timing model)
		a := scalarFromBigInt(u.A)
		ainv := new(secp256k1.ModNScalar).InverseValNonConst(a)
		rxS := scalarFromBigInt(rx)
		hS := scalarFromBigInt(h)
		mBlinded := ainv.Mul(rxS).Mul(hS)
		return scalarToBigInt(mBlinded), u, nil
	}
	return nil, nil, fmt.Errorf("blinding failed after %d attempts", maxBlindAttempts)
}

// Signature contains the signature values S & F
type Signature struct {
	S *big.Int
	F *Point
}

// Compress packs a Signature to a byte array of 65 bytes: S as 32
// little-endian bytes followed by the compressed F point (33 bytes).
func (s *Signature) Compress() [65]byte {
	var b [65]byte
	sBytes := s.S.Bytes()
	fBytes := s.F.Compress()
	copy(b[:32], swapEndianness(sBytes))
	copy(b[32:], fBytes[:])
	return b
}

// DecompressSignature unpacks a Signature from the given byte array of 65 bytes
func DecompressSignature(b [65]byte) (*Signature, error) {
	s := new(big.Int).SetBytes(swapEndianness(b[:32]))
	if err := validateScalar(s); err != nil {
		return nil, fmt.Errorf("s error: %s", err)
	}
	var fBytes [33]byte
	copy(fBytes[:], b[32:])
	f, err := DecompressPoint(fBytes)
	if err != nil {
		return nil, err
	}
	sig := &Signature{S: s, F: f}
	return sig, nil
}

// Unblind performs the unblinding operation of the blinded signature for the
// given UserSecretData
func Unblind(sBlind *big.Int, u *UserSecretData) (*Signature, error) {
	if err := validateScalar(sBlind); err != nil {
		return nil, fmt.Errorf("sBlind error: %s", err)
	}
	if u == nil {
		return nil, fmt.Errorf("user secret data can not be nil")
	}
	if err := validateScalar(u.A); err != nil {
		return nil, fmt.Errorf("u.A error: %s", err)
	}
	if err := validateScalar(u.B); err != nil {
		return nil, fmt.Errorf("u.B error: %s", err)
	}
	if err := u.F.isValid(); err != nil {
		return nil, fmt.Errorf("u.F %s", err)
	}

	// s = a s' + b, computed with constant-time scalar arithmetic as a and
	// b are secret
	a := scalarFromBigInt(u.A)
	bS := scalarFromBigInt(u.B)
	sB := scalarFromBigInt(sBlind)
	s := new(secp256k1.ModNScalar).Mul2(a, sB).Add(bS)

	return &Signature{
		S: scalarToBigInt(s),
		F: u.F,
	}, nil
}

// Verify checks the signature of the message m for the given PublicKey
func Verify(m *big.Int, s *Signature, q *PublicKey) bool {
	if m == nil || s == nil || q == nil {
		return false
	}
	// reject s.S outside [1, N) to rule out signature malleability via
	// s.S + kN variants of the same signature
	if err := validateScalar(s.S); err != nil {
		return false
	}
	if err := s.F.isValid(); err != nil {
		return false
	}
	if err := q.Point().isValid(); err != nil {
		return false
	}

	sG := G.Mul(s.S) // sG

	h := new(big.Int).SetBytes(keccak256(m.Bytes()))

	rx := new(big.Int).Mod(s.F.X, N)
	rxh := new(big.Int).Mul(rx, h)
	rxhMod := new(big.Int).Mod(rxh, N)
	// rxhG := G.Mul(rxh) // originally the paper uses G
	rxhG := q.Point().Mul(rxhMod)

	right := s.F.Add(rxhG)

	// check sG == R + rx h(m) Q (where R in this code is F)
	if bytes.Equal(sG.X.Bytes(), right.X.Bytes()) &&
		bytes.Equal(sG.Y.Bytes(), right.Y.Bytes()) {
		return true
	}
	return false
}
