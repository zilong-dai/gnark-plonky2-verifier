package main

/*
#include <stdlib.h>
#include <string.h>
*/
import "C"

import (
	"os"
	"unsafe"

	"github.com/zilong-dai/gnark-plonky2-verifier/cmd"
)

func main() {
	common_circuit_data, _ := os.ReadFile("../testdata/common_circuit_data.json")

	proof_with_public_inputs, _ := os.ReadFile("../testdata/proof_with_public_inputs.json")

	verifier_only_circuit_data, _ := os.ReadFile("../testdata/verifier_only_circuit_data.json")

	proofString, vkString := cmd.GenerateProof(string(common_circuit_data), string(proof_with_public_inputs), string(verifier_only_circuit_data))

	verifierResult := cmd.VerifyProof(proofString, vkString)

	if verifierResult != "true" {
		panic("verifier failed")
	}
}

//export GenerateGroth16Proof
func GenerateGroth16Proof(common_circuit_data *C.char, proof_with_public_inputs *C.char, verifier_only_circuit_data *C.char, vk_json_str *C.char) *C.char {
	proof_str, vk_str := cmd.GenerateProof(C.GoString(common_circuit_data), C.GoString(proof_with_public_inputs), C.GoString(verifier_only_circuit_data))

	vk_len := len(vk_str)

	// Copy data from C buffer to Go slice
	C.memcpy(unsafe.Pointer(vk_json_str), unsafe.Pointer(C.CString(vk_str)), C.size_t(vk_len))

	return C.CString(proof_str)
}

//export VerifyGroth16Proof
func VerifyGroth16Proof(proofString *C.char, vkString *C.char) *C.char {
	return C.CString(cmd.VerifyProof(C.GoString(proofString), C.GoString(vkString)))
}
