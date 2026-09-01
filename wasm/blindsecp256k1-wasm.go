package main

import (
	"fmt"
	"math/big"
	"syscall/js"

	blindsecp256k1 "github.com/vocdoni/go-blindsecp256k1"
)

func main() {
	c := make(chan struct{})
	println("WASM blindsecp256k1 initialized")
	registerCallbacks()
	<-c
}

func registerCallbacks() {
	js.Global().Set("wasmReady", js.FuncOf(ready))

	// blind & unblind uses: https://sci-hub.do/10.1109/ICCKE.2013.6682844
	js.Global().Set("wasmBlind", js.FuncOf(blind))
	js.Global().Set("wasmUnblind", js.FuncOf(unblind))
	js.Global().Set("wasmVerify", js.FuncOf(verify))
}

func stringToBigInt(s string) *big.Int {
	b, ok := new(big.Int).SetString(s, 10)
	if !ok {
		panic(fmt.Errorf("error parsing string *big.Int: %s", s))
	}
	return b
}

func ready(this js.Value, values []js.Value) interface{} {
	return "ready"
}

func blind(this js.Value, values []js.Value) interface{} {
	mStr := values[0].String()
	signerRxStr := values[1].String()
	signerRyStr := values[2].String()

	m := stringToBigInt(mStr)
	signerRx := stringToBigInt(signerRxStr)
	signerRy := stringToBigInt(signerRyStr)

	signerR := &blindsecp256k1.Point{
		X: signerRx,
		Y: signerRy,
	}

	mBlinded, user, err := blindsecp256k1.Blind(m, signerR)
	if err != nil {
		panic(err)
	}

	r := make(map[string]interface{})
	r["mBlinded"] = mBlinded.String()
	r["uA"] = user.A.String()
	r["uB"] = user.B.String()
	r["uFx"] = user.F.X.String()
	r["uFy"] = user.F.Y.String()
	return r
}

func unblind(this js.Value, values []js.Value) interface{} {
	sBlindStr := values[0].String()
	uAStr := values[1].String()
	uBStr := values[2].String()
	uFxStr := values[3].String()
	uFyStr := values[4].String()

	sBlind := stringToBigInt(sBlindStr)
	uA := stringToBigInt(uAStr)
	uB := stringToBigInt(uBStr)
	uFx := stringToBigInt(uFxStr)
	uFy := stringToBigInt(uFyStr)

	uF := &blindsecp256k1.Point{
		X: uFx,
		Y: uFy,
	}

	u := &blindsecp256k1.UserSecretData{
		A: uA,
		B: uB,
		F: uF,
	}

	sig := blindsecp256k1.Unblind(sBlind, u)

	r := make(map[string]interface{})
	r["s"] = sig.S.String()
	r["fx"] = sig.F.X.String()
	r["fy"] = sig.F.Y.String()
	return r
}

func verify(this js.Value, values []js.Value) interface{} {
	mStr := values[0].String()
	sigSStr := values[1].String()
	sigFxStr := values[2].String()
	sigFyStr := values[3].String()
	qxStr := values[4].String()
	qyStr := values[5].String()

	m := stringToBigInt(mStr)
	sigS := stringToBigInt(sigSStr)
	sigFx := stringToBigInt(sigFxStr)
	sigFy := stringToBigInt(sigFyStr)
	qx := stringToBigInt(qxStr)
	qy := stringToBigInt(qyStr)

	q := &blindsecp256k1.PublicKey{
		X: qx,
		Y: qy,
	}
	sig := &blindsecp256k1.Signature{
		S: sigS,
		F: &blindsecp256k1.Point{
			X: sigFx,
			Y: sigFy,
		},
	}
	verified := blindsecp256k1.Verify(m, sig, q)

	return verified
}
