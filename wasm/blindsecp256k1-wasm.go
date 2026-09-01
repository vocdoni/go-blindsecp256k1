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

func stringToBigInt(s string) (*big.Int, error) {
	b, ok := new(big.Int).SetString(s, 10)
	if !ok {
		return nil, fmt.Errorf("error parsing string *big.Int: %s", s)
	}
	return b, nil
}

// errMap reports a failure back to the JS caller instead of panicking, which
// would terminate the whole WASM runtime.
func errMap(err error) map[string]interface{} {
	return map[string]interface{}{"error": err.Error()}
}

func ready(this js.Value, values []js.Value) interface{} {
	return "ready"
}

func blind(this js.Value, values []js.Value) interface{} {
	m, err := stringToBigInt(values[0].String())
	if err != nil {
		return errMap(err)
	}
	signerRx, err := stringToBigInt(values[1].String())
	if err != nil {
		return errMap(err)
	}
	signerRy, err := stringToBigInt(values[2].String())
	if err != nil {
		return errMap(err)
	}

	signerR := &blindsecp256k1.Point{
		X: signerRx,
		Y: signerRy,
	}

	mBlinded, user, err := blindsecp256k1.Blind(m, signerR)
	if err != nil {
		return errMap(err)
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
	sBlind, err := stringToBigInt(values[0].String())
	if err != nil {
		return errMap(err)
	}
	uA, err := stringToBigInt(values[1].String())
	if err != nil {
		return errMap(err)
	}
	uB, err := stringToBigInt(values[2].String())
	if err != nil {
		return errMap(err)
	}
	uFx, err := stringToBigInt(values[3].String())
	if err != nil {
		return errMap(err)
	}
	uFy, err := stringToBigInt(values[4].String())
	if err != nil {
		return errMap(err)
	}

	uF := &blindsecp256k1.Point{
		X: uFx,
		Y: uFy,
	}

	u := &blindsecp256k1.UserSecretData{
		A: uA,
		B: uB,
		F: uF,
	}

	sig, err := blindsecp256k1.Unblind(sBlind, u)
	if err != nil {
		return errMap(err)
	}

	r := make(map[string]interface{})
	r["s"] = sig.S.String()
	r["fx"] = sig.F.X.String()
	r["fy"] = sig.F.Y.String()
	return r
}

func verify(this js.Value, values []js.Value) interface{} {
	m, err := stringToBigInt(values[0].String())
	if err != nil {
		return errMap(err)
	}
	sigS, err := stringToBigInt(values[1].String())
	if err != nil {
		return errMap(err)
	}
	sigFx, err := stringToBigInt(values[2].String())
	if err != nil {
		return errMap(err)
	}
	sigFy, err := stringToBigInt(values[3].String())
	if err != nil {
		return errMap(err)
	}
	qx, err := stringToBigInt(values[4].String())
	if err != nil {
		return errMap(err)
	}
	qy, err := stringToBigInt(values[5].String())
	if err != nil {
		return errMap(err)
	}

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
