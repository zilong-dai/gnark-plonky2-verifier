package main

import "C"

import (
	"os"

	"github.com/cf/gnark-plonky2-verifier/cmd"
)

func main() {
	common_circuit_data, _ := os.ReadFile("../testdata/common_circuit_data.json")

	proof_with_public_inputs, _ := os.ReadFile("../testdata/proof_with_public_inputs.json")

	verifier_only_circuit_data, _ := os.ReadFile("../testdata/verifier_only_circuit_data.json")

	proofString := cmd.GenerateProof(string(common_circuit_data), string(proof_with_public_inputs), string(verifier_only_circuit_data))

	verifierResult := cmd.VerifyProof(proofString)

	if verifierResult != "true" {
		panic("verifier failed")
	}
}

//export GenerateGroth16Proof
func GenerateGroth16Proof(common_circuit_data *C.char, proof_with_public_inputs *C.char, verifier_only_circuit_data *C.char) *C.char {

	return C.CString(cmd.GenerateProof(C.GoString(common_circuit_data), C.GoString(proof_with_public_inputs), C.GoString(verifier_only_circuit_data)))
}

//export VerifyGroth16Proof
func VerifyGroth16Proof(proofString *C.char) *C.char {
	return C.CString(cmd.VerifyProof(C.GoString(proofString)))
}
