package blindsecp256k1

import (
	"math/big"
	"testing"
)

func BenchmarkNewPrivateKey(b *testing.B) {
	for b.Loop() {
		if _, err := NewPrivateKey(); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkBlind(b *testing.B) {
	_, signerR, err := NewRequestParameters()
	if err != nil {
		b.Fatal(err)
	}
	m := new(big.Int).SetBytes(keccak256([]byte("benchmark")))
	b.ResetTimer()
	for b.Loop() {
		if _, _, err := Blind(m, signerR); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkBlindSign(b *testing.B) {
	sk, err := NewPrivateKey()
	if err != nil {
		b.Fatal(err)
	}
	k, signerR, err := NewRequestParameters()
	if err != nil {
		b.Fatal(err)
	}
	m := new(big.Int).SetBytes(keccak256([]byte("benchmark")))
	mBlinded, _, err := Blind(m, signerR)
	if err != nil {
		b.Fatal(err)
	}
	b.ResetTimer()
	for b.Loop() {
		if _, err := sk.BlindSign(mBlinded, k); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkUnblind(b *testing.B) {
	sk, err := NewPrivateKey()
	if err != nil {
		b.Fatal(err)
	}
	k, signerR, err := NewRequestParameters()
	if err != nil {
		b.Fatal(err)
	}
	m := new(big.Int).SetBytes(keccak256([]byte("benchmark")))
	mBlinded, u, err := Blind(m, signerR)
	if err != nil {
		b.Fatal(err)
	}
	sBlind, err := sk.BlindSign(mBlinded, k)
	if err != nil {
		b.Fatal(err)
	}
	b.ResetTimer()
	for b.Loop() {
		if _, err := Unblind(sBlind, u); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkVerify(b *testing.B) {
	sk, err := NewPrivateKey()
	if err != nil {
		b.Fatal(err)
	}
	pk := sk.Public()
	k, signerR, err := NewRequestParameters()
	if err != nil {
		b.Fatal(err)
	}
	m := new(big.Int).SetBytes(keccak256([]byte("benchmark")))
	mBlinded, u, err := Blind(m, signerR)
	if err != nil {
		b.Fatal(err)
	}
	sBlind, err := sk.BlindSign(mBlinded, k)
	if err != nil {
		b.Fatal(err)
	}
	sig, err := Unblind(sBlind, u)
	if err != nil {
		b.Fatal(err)
	}
	b.ResetTimer()
	for b.Loop() {
		if !Verify(m, sig, pk) {
			b.Fatal("verification failed")
		}
	}
}
