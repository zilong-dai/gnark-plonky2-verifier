package main

/*
#include <stdlib.h> // Include C standard library, if necessary
#include <string.h>
typedef struct {
    char* proof;
    char* vk;
} Groth16ProofWithVK;
*/
import "C"
import (
	// "os"

	"github.com/cf/gnark-plonky2-verifier/worker"
)

type Groth16ProofWithVK struct {
  Proof string
  Vk string
}

//export GenerateGroth16Proof
func GenerateGroth16Proof(common_circuit_data *C.char, proof_with_public_inputs *C.char, verifier_only_circuit_data *C.char) *C.Groth16ProofWithVK {
  proof_str, vk_str := worker.GenerateProof(C.GoString(common_circuit_data), C.GoString(proof_with_public_inputs), C.GoString(verifier_only_circuit_data))

  cProofWithVk := (*C.Groth16ProofWithVK)(C.malloc(C.sizeof_Groth16ProofWithVK))
  cProofWithVk.proof = C.CString(proof_str)
  cProofWithVk.vk = C.CString(vk_str)
	return cProofWithVk
}

//export VerifyGroth16Proof
func VerifyGroth16Proof(proofString *C.char, vkString *C.char) *C.char {
	return C.CString(worker.VerifyProof(C.GoString(proofString), C.GoString(vkString)))
}

func main() {
	// common_circuit_data, _ := os.ReadFile("../testdata/common_circuit_data.json")
  //
	// proof_with_public_inputs, _ := os.ReadFile("../testdata/proof_with_public_inputs.json")
  //
	// verifier_only_circuit_data, _ := os.ReadFile("../testdata/verifier_only_circuit_data.json")
  //
	// proofString := worker.GenerateProof(string(common_circuit_data), string(proof_with_public_inputs), string(verifier_only_circuit_data))
  //
	// verifierResult := worker.VerifyProof(proofString)
  //
	// if verifierResult != "true" {
	// 	panic("verifier failed")
	// }
}
