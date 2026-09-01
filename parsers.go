package blindsecp256k1

import (
	"encoding/json"
	"fmt"
	"math/big"

	secp256k1 "github.com/decred/dcrd/dcrec/secp256k1/v4"
)

// swapEndianness swaps the order of the bytes in the slice.
func swapEndianness(b []byte) []byte {
	o := make([]byte, len(b))
	for i := range b {
		o[len(b)-1-i] = b[i]
	}
	return o
}

// MarshalJSON implements the json marshaler for the Point
func (p Point) MarshalJSON() ([]byte, error) {
	if p.X == nil || p.Y == nil {
		return nil, fmt.Errorf("can not marshal Point with nil coordinates")
	}
	return json.Marshal(&struct {
		X string `json:"x"`
		Y string `json:"y"`
	}{
		X: p.X.String(),
		Y: p.Y.String(),
	})
}

// UnmarshalJSON implements the json unmarshaler for the Point. The decoded
// point is validated to be on the secp256k1 curve.
func (p *Point) UnmarshalJSON(b []byte) error {
	// decode into an allocated struct (not a pointer) so JSON null cannot
	// leave it nil: it falls through to the SetString parse errors below
	var aux struct {
		X string `json:"x"`
		Y string `json:"y"`
	}
	err := json.Unmarshal(b, &aux)
	if err != nil {
		return err
	}
	x, ok := new(big.Int).SetString(aux.X, 10)
	if !ok {
		return fmt.Errorf("can not parse Point.X %s", aux.X)
	}
	y, ok := new(big.Int).SetString(aux.Y, 10)
	if !ok {
		return fmt.Errorf("can not parse Point.Y %s", aux.Y)
	}
	aux2 := &Point{X: x, Y: y}
	if err := aux2.isValid(); err != nil {
		return err
	}
	p.X = x
	p.Y = y
	return nil
}

// Bytes returns the compressed Point as a byte slice of length 33 (see
// Compress for the exact encoding).
func (p *Point) Bytes() []byte {
	b := p.Compress()
	return b[:]
}

// NewPointFromBytes returns a new *Point from the given compressed Point
// encoding of length 33 (see Compress for the exact encoding).
func NewPointFromBytes(b []byte) (*Point, error) {
	if len(b) != 33 {
		return nil, fmt.Errorf("can not parse bytes to Point,"+
			" expected byte array of length %d, current %d",
			33, len(b))
	}

	var pBytes [33]byte
	copy(pBytes[:], b[:])
	return DecompressPoint(pBytes)
}

// MarshalJSON implements the json marshaler for the PublicKey
func (pk PublicKey) MarshalJSON() ([]byte, error) {
	return json.Marshal(pk.Point())
}

// UnmarshalJSON implements the json unmarshaler for the PublicKey
func (pk *PublicKey) UnmarshalJSON(b []byte) error {
	var point *Point
	err := json.Unmarshal(b, &point)
	if err != nil {
		return err
	}
	if point == nil {
		// JSON null bypasses Point.UnmarshalJSON and leaves the pointer nil
		return fmt.Errorf("can not parse PublicKey: null")
	}
	pk.X = point.X
	pk.Y = point.Y
	return nil
}

// Bytes returns the compressed PublicKey as a byte slice of length 33 (see
// Point.Compress for the exact encoding).
func (pk *PublicKey) Bytes() []byte {
	return pk.Point().Bytes()
}

// NewPublicKeyFromBytes returns a new *PublicKey from the given compressed
// encoding of length 33 (see Point.Compress for the exact encoding).
func NewPublicKeyFromBytes(b []byte) (*PublicKey, error) {
	p, err := NewPointFromBytes(b)
	if err != nil {
		return nil, err
	}
	pk := PublicKey(*p)
	return &pk, nil
}

// NewPublicKeyFromECDSA returns a *PublicKey from a SEC1-serialized ECDSA
// public key (as produced by the ethereum/standard ECDSA implementations).
func NewPublicKeyFromECDSA(b []byte) (*PublicKey, error) {
	pub, err := secp256k1.ParsePubKey(b)
	if err != nil {
		return nil, err
	}
	pk := new(PublicKey)
	pk.X = pub.X()
	pk.Y = pub.Y()
	return pk, nil
}

// MarshalJSON implements the json marshaler for the Signature
func (sig Signature) MarshalJSON() ([]byte, error) {
	if sig.S == nil || sig.F == nil || sig.F.X == nil || sig.F.Y == nil {
		return nil, fmt.Errorf("can not marshal Signature with nil values")
	}
	return json.Marshal(&struct {
		S string `json:"s"`
		F struct {
			X string `json:"x"`
			Y string `json:"y"`
		} `json:"f"`
	}{
		S: sig.S.String(),
		F: struct {
			X string `json:"x"`
			Y string `json:"y"`
		}{
			X: sig.F.X.String(),
			Y: sig.F.Y.String(),
		},
	})
}

// UnmarshalJSON implements the json unmarshaler for the Signature. The
// decoded S is validated to be in [1, N) and the decoded F to be on the
// secp256k1 curve.
func (sig *Signature) UnmarshalJSON(b []byte) error {
	// decode into an allocated struct (not a pointer) so JSON null cannot
	// leave it nil: it falls through to the SetString parse errors below
	var aux struct {
		S string `json:"s"`
		F struct {
			X string `json:"x"`
			Y string `json:"y"`
		} `json:"f"`
	}
	err := json.Unmarshal(b, &aux)
	if err != nil {
		return err
	}

	s, ok := new(big.Int).SetString(aux.S, 10)
	if !ok {
		return fmt.Errorf("can not parse sig.S %s", aux.S)
	}
	if err := validateScalar(s); err != nil {
		return fmt.Errorf("sig.S error: %s", err)
	}

	x, ok := new(big.Int).SetString(aux.F.X, 10)
	if !ok {
		return fmt.Errorf("can not parse sig.F.X %s", aux.F.X)
	}
	y, ok := new(big.Int).SetString(aux.F.Y, 10)
	if !ok {
		return fmt.Errorf("can not parse sig.F.Y %s", aux.F.Y)
	}
	f := &Point{X: x, Y: y}
	if err := f.isValid(); err != nil {
		return fmt.Errorf("sig.F %s", err)
	}
	sig.S = s
	sig.F = f
	return nil
}

// Bytes returns the compressed Signature as a byte slice of length 65 (see
// Compress for the exact encoding).
func (sig *Signature) Bytes() []byte {
	s := sig.Compress()
	return s[:]
}

// NewSignatureFromBytes returns a new *Signature from the given compressed
// Signature encoding of length 65 (see Compress for the exact encoding).
func NewSignatureFromBytes(b []byte) (*Signature, error) {
	if len(b) != 65 {
		return nil,
			fmt.Errorf("can not parse bytes to Signature,"+
				" expected byte array of length %d, current %d",
				65, len(b))
	}
	var sigBytes [65]byte
	copy(sigBytes[:], b)
	return DecompressSignature(sigBytes)
}
