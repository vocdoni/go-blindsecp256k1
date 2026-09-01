package blindsecp256k1

import (
	"bytes"
	"encoding/json"
	"math/big"
	"testing"
)

// The fuzz targets assert two properties on every parser: it never panics on
// arbitrary input, and every accepted input re-encodes byte-identically
// (canonical round-trip).

func FuzzDecompressPoint(f *testing.F) {
	gb := G.Compress()
	f.Add(gb[:])
	p1234 := G.Mul(big.NewInt(1234)).Compress()
	f.Add(p1234[:])
	f.Add(make([]byte, 33))

	f.Fuzz(func(t *testing.T, data []byte) {
		p, err := NewPointFromBytes(data)
		if err != nil {
			return
		}
		if !bytes.Equal(p.Bytes(), data) {
			t.Fatalf("decode/encode round-trip mismatch: %x", data)
		}
	})
}

func FuzzSignatureFromBytes(f *testing.F) {
	sig := &Signature{S: big.NewInt(9876), F: G.Mul(big.NewInt(1234))}
	f.Add(sig.Bytes())
	f.Add(make([]byte, 65))

	f.Fuzz(func(t *testing.T, data []byte) {
		s, err := NewSignatureFromBytes(data)
		if err != nil {
			return
		}
		if !bytes.Equal(s.Bytes(), data) {
			t.Fatalf("decode/encode round-trip mismatch: %x", data)
		}
	})
}

func FuzzPointFromBytesUncompressed(f *testing.F) {
	f.Add(G.Mul(big.NewInt(1234)).BytesUncompressed())
	f.Add(make([]byte, 64))

	f.Fuzz(func(t *testing.T, data []byte) {
		p, err := NewPointFromBytesUncompressed(data)
		if err != nil {
			return
		}
		if !bytes.Equal(p.BytesUncompressed(), data) {
			t.Fatalf("decode/encode round-trip mismatch: %x", data)
		}
	})
}

func FuzzPointUnmarshalJSON(f *testing.F) {
	jb, _ := json.Marshal(G.Mul(big.NewInt(1234)))
	f.Add(jb)
	f.Add([]byte(`{"x":"3","y":"3"}`))
	f.Add([]byte(`{"x":"-1","y":"foo"}`))
	f.Add([]byte(`null`))
	f.Add([]byte(`{"x":null,"y":null}`))

	f.Fuzz(func(t *testing.T, data []byte) {
		var p Point
		if err := json.Unmarshal(data, &p); err != nil {
			return
		}
		jb, err := json.Marshal(p)
		if err != nil {
			t.Fatalf("accepted point failed to marshal: %s", data)
		}
		var p2 Point
		if err := json.Unmarshal(jb, &p2); err != nil {
			t.Fatalf("re-marshaled point failed to unmarshal: %s", jb)
		}
		if p.X.Cmp(p2.X) != 0 || p.Y.Cmp(p2.Y) != 0 {
			t.Fatalf("JSON round-trip mismatch: %s", data)
		}
	})
}
