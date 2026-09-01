function test() {
	let m = "1952805748";

	console.log("using: https://sci-hub.do/10.1109/ICCKE.2013.6682844");
	// R would be received from the Signer
	let signerRx = "17814783168156809976981325336969869272256267559847863501362979416582031885685";
	let signerRy = "30466749656160766323378925376290982172805224557687141285291181575233995759897";
	let blindRes = wasmBlind(m, signerRx, signerRy);
	if (blindRes.error) {
		console.error("blind failed:", blindRes.error);
		return;
	}
	console.log("blind", blindRes);

	// Q & sBlind would be received from the Signer. This sBlind is an
	// illustrative canonical scalar (any value in [0, N)); it does not
	// correspond to the random blinding factors generated above, so the
	// unblinded signature is not verifiable (see the note below).
	let signerQx = "91217724741799691300838336208439702708830781279546234509900618215893368170964";
	let signerQy = "10647409378909561143830454293907272341812664755625953321604115356883317910171";
	let sBlind = "15599896837383177000557157063444607810465710161429966974447777494331949586669";
	let unblindRes = wasmUnblind(sBlind, blindRes.uA, blindRes.uB, blindRes.uFx, blindRes.uFy);
	if (unblindRes.error) {
		console.error("unblind failed:", unblindRes.error);
		return;
	}
	console.log("unblind", unblindRes);

	// wasmVerify method not used here because the hardcoded values would
	// not match with the random generated values from the 'blind' method
	// let verified = wasmVerify(m, unblindRes.s, unblindRes.fx, unblindRes.fy, signerQx, signerQy);
	// console.log("verify", verified);
}
