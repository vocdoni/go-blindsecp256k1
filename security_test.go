package blindsecp256k1

import (
	"encoding/hex"
	"encoding/json"
	"math/big"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func hexToBig(t *testing.T, s string) *big.Int {
	t.Helper()
	v, ok := new(big.Int).SetString(s, 16)
	require.True(t, ok)
	return v
}

// TestDeterministicVector freezes a full protocol run with fixed scalars. The
// blinding math is recomputed here with an independent big.Int implementation,
// cross-checking the package's ModNScalar arithmetic, and the resulting bytes
// are pinned so any regression or cross-implementation divergence surfaces.
func TestDeterministicVector(t *testing.T) {
	d := hexToBig(t, "1c2f6b6f7f6c2e2c8a1b3d4e5f60718293a4b5c6d7e8f90a1b2c3d4e5f607182")
	k := hexToBig(t, "2a3b4c5d6e7f808192a3b4c5d6e7f8091a2b3c4d5e6f708192a3b4c5d6e7f809")
	a := hexToBig(t, "3c4d5e6f708192a3b4c5d6e7f8091a2b3c4d5e6f708192a3b4c5d6e7f8091a2b")
	b := hexToBig(t, "4d5e6f708192a3b4c5d6e7f8091a2b3c4d5e6f708192a3b4c5d6e7f8091a2b3c")
	m := new(big.Int).SetBytes([]byte("go-blindsecp256k1 deterministic test vector"))

	sk := PrivateKey(*d)
	signerR := G.Mul(k)

	// reference blinding implementation using plain big.Int arithmetic
	F := signerR.Mul(a).Add(G.Mul(b))
	rx := new(big.Int).Mod(F.X, N)
	h := new(big.Int).SetBytes(keccak256(m.Bytes()))
	ainv := new(big.Int).ModInverse(a, N)
	mBlinded := new(big.Int).Mod(new(big.Int).Mul(new(big.Int).Mul(ainv, rx), h), N)

	sBlind, err := sk.BlindSign(mBlinded, k)
	require.Nil(t, err)
	sig, err := Unblind(sBlind, &UserSecretData{A: a, B: b, F: F})
	require.Nil(t, err)
	require.True(t, Verify(m, sig, sk.Public()))

	assert.Equal(t,
		"53085f4ba9e4a214459de38b691be2aea05834a26449b6e9d1aab9058007ae85",
		mBlinded.Text(16))
	assert.Equal(t,
		"d37fcf820bdb8a017688020bbe715f5abc50c292d133e50a22ab4cf64bc33e5c",
		sBlind.Text(16))
	assert.Equal(t,
		"a6c4545a4a630a952dc7fb513b3b40c12cdc5dbd303e65ddf387b222ce37b47c"+
			"547df0ab07e473bee1aee01e4adf593e68789162aa1764946730623309a6800300",
		hex.EncodeToString(sig.Bytes()))
	assert.Equal(t,
		"f148d436f87c063b0039aacba7cb99c0158f7bf7524a11c8c9d03c4a7404189301",
		hex.EncodeToString(sk.Public().Bytes()))
}

// TestFlowProperty runs the full protocol many times with fresh randomness:
// every run must verify, every signature S must be a canonical scalar, and
// every encoding must round-trip.
func TestFlowProperty(t *testing.T) {
	sk, err := NewPrivateKey()
	require.Nil(t, err)
	pk := sk.Public()

	for i := 0; i < 100; i++ {
		k, signerR, err := NewRequestParameters()
		require.Nil(t, err)

		m := new(big.Int).SetBytes(keccak256(big.NewInt(int64(i)).Bytes()))
		mBlinded, u, err := Blind(m, signerR)
		require.Nil(t, err)

		sBlind, err := sk.BlindSign(mBlinded, k)
		require.Nil(t, err)

		sig, err := Unblind(sBlind, u)
		require.Nil(t, err)
		require.True(t, Verify(m, sig, pk))

		// canonical scalar invariant
		require.Nil(t, validateScalar(sig.S))

		// compressed round-trip
		sig2, err := NewSignatureFromBytes(sig.Bytes())
		require.Nil(t, err)
		require.Equal(t, sig, sig2)

		// uncompressed round-trip
		sig3, err := NewSignatureFromBytesUncompressed(sig.BytesUncompressed())
		require.Nil(t, err)
		require.Equal(t, sig, sig3)

		// JSON round-trip
		jb, err := json.Marshal(sig)
		require.Nil(t, err)
		var sig4 Signature
		require.Nil(t, json.Unmarshal(jb, &sig4))
		require.Equal(t, *sig, sig4)
	}
}

// TestNewPrivateKeyNeverFails is a regression test for the old exact-32-byte
// scalar check, which made key generation (and blinding) fail for ~0.4% of
// perfectly valid random scalars.
func TestNewPrivateKeyNeverFails(t *testing.T) {
	for i := 0; i < 2000; i++ {
		sk, err := NewPrivateKey()
		require.Nil(t, err)
		require.Nil(t, validateScalar(sk.BigInt()))
	}
}

func testSignatureFixture(t *testing.T) (*big.Int, *Signature, *PublicKey) {
	t.Helper()
	sk, err := NewPrivateKey()
	require.Nil(t, err)
	k, signerR, err := NewRequestParameters()
	require.Nil(t, err)
	m := new(big.Int).SetBytes(keccak256([]byte("tamper test")))
	mBlinded, u, err := Blind(m, signerR)
	require.Nil(t, err)
	sBlind, err := sk.BlindSign(mBlinded, k)
	require.Nil(t, err)
	sig, err := Unblind(sBlind, u)
	require.Nil(t, err)
	require.True(t, Verify(m, sig, sk.Public()))
	return m, sig, sk.Public()
}

func TestVerifyTampered(t *testing.T) {
	m, sig, pk := testSignatureFixture(t)

	// tampered S
	badS := &Signature{S: new(big.Int).Add(sig.S, big.NewInt(1)), F: sig.F}
	assert.False(t, Verify(m, badS, pk))

	// malleated S (S + N encodes the same residue): must be rejected
	malleated := &Signature{S: new(big.Int).Add(sig.S, N), F: sig.F}
	assert.False(t, Verify(m, malleated, pk))

	// tampered F (another valid curve point)
	badF := &Signature{S: sig.S, F: G.Mul(big.NewInt(42))}
	assert.False(t, Verify(m, badF, pk))

	// off-curve F
	offCurve := &Signature{S: sig.S, F: &Point{X: big.NewInt(1), Y: big.NewInt(1)}}
	assert.False(t, Verify(m, offCurve, pk))

	// wrong message
	assert.False(t, Verify(new(big.Int).Add(m, big.NewInt(1)), sig, pk))

	// wrong public key
	sk2, err := NewPrivateKey()
	require.Nil(t, err)
	assert.False(t, Verify(m, sig, sk2.Public()))

	// nil and zero inputs
	assert.False(t, Verify(nil, sig, pk))
	assert.False(t, Verify(m, nil, pk))
	assert.False(t, Verify(m, sig, nil))
	assert.False(t, Verify(m, &Signature{S: big.NewInt(0), F: sig.F}, pk))
	assert.False(t, Verify(m, &Signature{S: nil, F: sig.F}, pk))
	assert.False(t, Verify(m, &Signature{S: sig.S, F: nil}, pk))
	assert.False(t, Verify(m, sig, (*PublicKey)(&Point{X: big.NewInt(0), Y: big.NewInt(0)})))
}

func TestBlindInvalidInputs(t *testing.T) {
	m := big.NewInt(1234)

	// nil / invalid signerR
	_, _, err := Blind(m, &Point{X: big.NewInt(1), Y: big.NewInt(1)})
	assert.NotNil(t, err)
	_, _, err = Blind(m, &Point{X: big.NewInt(0), Y: big.NewInt(0)})
	assert.NotNil(t, err)
	_, _, err = Blind(m, &Point{X: nil, Y: nil})
	assert.NotNil(t, err)
	_, _, err = Blind(nil, G)
	assert.NotNil(t, err)

	// x/y outside the field are rejected even if congruent to a curve point
	beyond := &Point{X: new(big.Int).Add(G.X, P), Y: G.Y}
	_, _, err = Blind(m, beyond)
	assert.NotNil(t, err)
}

func TestUnblindInvalidInputs(t *testing.T) {
	_, sig, _ := testSignatureFixture(t)
	valid := &UserSecretData{A: big.NewInt(2), B: big.NewInt(3), F: G.Mul(big.NewInt(5))}

	_, err := Unblind(big.NewInt(1), nil)
	assert.NotNil(t, err)
	_, err = Unblind(nil, valid)
	assert.NotNil(t, err)
	_, err = Unblind(big.NewInt(0), valid)
	assert.NotNil(t, err)
	_, err = Unblind(N, valid)
	assert.NotNil(t, err)
	_, err = Unblind(big.NewInt(1), &UserSecretData{A: nil, B: big.NewInt(1), F: G})
	assert.NotNil(t, err)
	_, err = Unblind(big.NewInt(1), &UserSecretData{
		A: big.NewInt(1), B: big.NewInt(1),
		F: &Point{X: big.NewInt(1), Y: big.NewInt(1)},
	})
	assert.NotNil(t, err)

	// sanity: valid inputs still work
	_, err = Unblind(sig.S, valid)
	assert.Nil(t, err)
}

func TestDecompressPointInvalid(t *testing.T) {
	// parity byte out of range
	b := G.Compress()
	b[32] = 2
	_, err := DecompressPoint(b)
	assert.NotNil(t, err)

	// x >= P
	var xOverflow [33]byte
	P.FillBytes(xOverflow[:32])
	_, err = DecompressPoint(xOverflow)
	assert.NotNil(t, err)

	// x = 0 is not the abscissa of any secp256k1 point
	var zeroX [33]byte
	_, err = DecompressPoint(zeroX)
	assert.NotNil(t, err)
}

func TestParsersWrongLength(t *testing.T) {
	for _, n := range []int{0, 32, 34, 64} {
		_, err := NewPointFromBytes(make([]byte, n))
		assert.NotNil(t, err)
		_, err = NewPublicKeyFromBytes(make([]byte, n))
		assert.NotNil(t, err)
	}
	for _, n := range []int{0, 64, 66, 96} {
		_, err := NewSignatureFromBytes(make([]byte, n))
		assert.NotNil(t, err)
	}
	for _, n := range []int{0, 33, 63, 65} {
		_, err := NewPointFromBytesUncompressed(make([]byte, n))
		assert.NotNil(t, err)
	}
	for _, n := range []int{0, 65, 95, 97} {
		_, err := NewSignatureFromBytesUncompressed(make([]byte, n))
		assert.NotNil(t, err)
	}
}

func TestUncompressedValidation(t *testing.T) {
	// off-curve point must be rejected now
	offCurve := &Point{X: big.NewInt(3), Y: big.NewInt(3)}
	_, err := NewPointFromBytesUncompressed(offCurve.BytesUncompressed())
	assert.NotNil(t, err)

	// signature with S = 0 must be rejected
	sig := &Signature{S: big.NewInt(0), F: G}
	_, err = NewSignatureFromBytesUncompressed(sig.BytesUncompressed())
	assert.NotNil(t, err)

	// compressed signature with S = 0 must be rejected too
	var zeroSig [65]byte
	fB := G.Compress()
	copy(zeroSig[32:], fB[:])
	_, err = DecompressSignature(zeroSig)
	assert.NotNil(t, err)
}

func TestJSONValidation(t *testing.T) {
	var p Point
	// malformed values
	assert.NotNil(t, json.Unmarshal([]byte(`{"x":"foo","y":"1"}`), &p))
	assert.NotNil(t, json.Unmarshal([]byte(`{"x":"1","y":""}`), &p))
	assert.NotNil(t, json.Unmarshal([]byte(`{}`), &p))
	// off-curve
	assert.NotNil(t, json.Unmarshal([]byte(`{"x":"3","y":"3"}`), &p))
	// negative coordinates
	assert.NotNil(t, json.Unmarshal([]byte(`{"x":"-1","y":"2"}`), &p))
	// coordinates >= P (G.X + P is congruent to G.X but non-canonical)
	beyondX := new(big.Int).Add(G.X, P)
	assert.NotNil(t, json.Unmarshal(
		[]byte(`{"x":"`+beyondX.String()+`","y":"`+G.Y.String()+`"}`), &p))

	var sig Signature
	// S = 0 and S >= N
	fJSON := `{"x":"` + G.X.String() + `","y":"` + G.Y.String() + `"}`
	assert.NotNil(t, json.Unmarshal([]byte(`{"s":"0","f":`+fJSON+`}`), &sig))
	assert.NotNil(t, json.Unmarshal([]byte(`{"s":"`+N.String()+`","f":`+fJSON+`}`), &sig))
	// off-curve F
	assert.NotNil(t, json.Unmarshal([]byte(`{"s":"1","f":{"x":"3","y":"3"}}`), &sig))

	// marshaling nil values errors instead of panicking
	_, err := json.Marshal(Point{})
	assert.NotNil(t, err)
	_, err = json.Marshal(Signature{})
	assert.NotNil(t, err)
	_, err = json.Marshal(Signature{S: big.NewInt(1), F: &Point{}})
	assert.NotNil(t, err)
}

func TestNewPublicKeyFromECDSAInvalid(t *testing.T) {
	_, err := NewPublicKeyFromECDSA([]byte{})
	assert.NotNil(t, err)
	_, err = NewPublicKeyFromECDSA(make([]byte, 65))
	assert.NotNil(t, err)
}
