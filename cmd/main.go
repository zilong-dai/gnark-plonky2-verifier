package main

/*
#include <stdlib.h> // Include C standard library, if necessary
*/
import "C"
import (
	"bytes"
	"encoding/hex"
	"fmt"
	"math/big"
	// "unsafe"

	gl "github.com/cf/gnark-plonky2-verifier/goldilocks"
	"github.com/cf/gnark-plonky2-verifier/types"
	"github.com/cf/gnark-plonky2-verifier/variables"
	"github.com/cf/gnark-plonky2-verifier/verifier"
	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
)

type CRVerifierCircuit struct {
	PublicInputs            []frontend.Variable               `gnark:",public"`
	Proof                   variables.Proof                   `gnark:"-"`
	VerifierOnlyCircuitData variables.VerifierOnlyCircuitData `gnark:"-"`

	OriginalPublicInputs []gl.Variable `gnark:"_"`

	// This is configuration for the circuit, it is a constant not a variable
	CommonCircuitData types.CommonCircuitData
}

func (c *CRVerifierCircuit) Define(api frontend.API) error {
	verifierChip := verifier.NewVerifierChip(api, c.CommonCircuitData)
	if len(c.PublicInputs) != 2 {
		panic("invalid public inputs, should contain 2 BLS12_381 elements")
	}
	if len(c.OriginalPublicInputs) != 8 {
		panic("invalid original public inputs, should contain 8 goldilocks elements")
	}

	two_to_32 := new(big.Int).SetInt64(1 << 32)
	two_to_31 := new(big.Int).SetInt64(1 << 31)
	two_to_63 := new(big.Int).Mul(two_to_31, two_to_32)

	blockStateHashAcc := frontend.Variable(0)
	sighashAcc := frontend.Variable(0)
	for i := 3; i >= 0; i-- {
		blockStateHashAcc = api.MulAcc(c.OriginalPublicInputs[i].Limb, blockStateHashAcc, two_to_63)
	}
	for i := 7; i >= 4; i-- {
		sighashAcc = api.MulAcc(c.OriginalPublicInputs[i].Limb, sighashAcc, two_to_63)
	}

	api.AssertIsEqual(c.PublicInputs[0], blockStateHashAcc)
	api.AssertIsEqual(c.PublicInputs[1], sighashAcc)

	verifierChip.Verify(c.Proof, c.OriginalPublicInputs, c.VerifierOnlyCircuitData)

	return nil
}

//export GenerateGroth16Proof
func GenerateGroth16Proof(path *C.char) *C.char {
	commonCircuitData := types.ReadCommonCircuitData(C.GoString(path) + "/common_circuit_data.json")

	proofWithPis := variables.DeserializeProofWithPublicInputs(types.ReadProofWithPublicInputs(C.GoString(path) + "/proof_with_public_inputs.json"))
	verifierOnlyCircuitData := variables.DeserializeVerifierOnlyCircuitData(types.ReadVerifierOnlyCircuitData(C.GoString(path) + "/verifier_only_circuit_data.json"))

	circuit := CRVerifierCircuit{
		PublicInputs:            make([]frontend.Variable, 2),
		Proof:                   proofWithPis.Proof,
		OriginalPublicInputs:    proofWithPis.PublicInputs,
		VerifierOnlyCircuitData: verifierOnlyCircuitData,
		CommonCircuitData:       commonCircuitData,
	}

	rawProofWithPis := types.ReadProofWithPublicInputs(C.GoString(path) + "/proof_with_public_inputs.json")
	proofWithPis = variables.DeserializeProofWithPublicInputs(rawProofWithPis)
	verifierOnlyCircuitData = variables.DeserializeVerifierOnlyCircuitData(types.ReadVerifierOnlyCircuitData(C.GoString(path) + "/verifier_only_circuit_data.json"))

	two_to_32 := new(big.Int).SetInt64(1 << 32)
	two_to_31 := new(big.Int).SetInt64(1 << 31)
	two_to_63 := new(big.Int).Mul(two_to_31, two_to_32)

	blockStateHashAcc := big.NewInt(0)
	sighashAcc := big.NewInt(0)
	for i := 3; i >= 0; i-- {
		blockStateHashAcc = new(big.Int).Mul(blockStateHashAcc, two_to_63)
		blockStateHashAcc = new(big.Int).Add(blockStateHashAcc, new(big.Int).SetUint64(rawProofWithPis.PublicInputs[i]))
	}
	for i := 7; i >= 4; i-- {
		sighashAcc = new(big.Int).Mul(sighashAcc, two_to_63)
		sighashAcc = new(big.Int).Add(sighashAcc, new(big.Int).SetUint64(rawProofWithPis.PublicInputs[i]))
	}
	blockStateHash := frontend.Variable(blockStateHashAcc)
	sighash := frontend.Variable(sighashAcc)
	assignment := CRVerifierCircuit{
		PublicInputs:            []frontend.Variable{blockStateHash, sighash},
		Proof:                   proofWithPis.Proof,
		OriginalPublicInputs:    proofWithPis.PublicInputs,
		VerifierOnlyCircuitData: verifierOnlyCircuitData,
	}

	cs, err := frontend.Compile(ecc.BLS12_381.ScalarField(), r1cs.NewBuilder, &circuit)
	if err != nil {
		panic(err)
	}
	pk, vk, err := groth16.Setup(cs)
	if err != nil {
		panic(err)
	}

	witness, err := frontend.NewWitness(&assignment, ecc.BLS12_381.ScalarField())
	if err != nil {
		panic(err)
	}
	proof, err := groth16.Prove(cs, pk, witness)
	publicWitness, err := witness.Public()
	if err != nil {
		panic(err)
	}

	err = groth16.Verify(proof, vk, publicWitness)
	if err != nil {
		panic(err)
	}

	var piBuf bytes.Buffer
	publicWitness.WriteTo(&piBuf)
	piBytes := piBuf.Bytes()

	var proofBuf bytes.Buffer
	proof.WriteTo(&proofBuf)
	proofBytes := proofBuf.Bytes()

	var vkBuf bytes.Buffer
	vk.WriteTo(&vkBuf)
	vkBytes := vkBuf.Bytes()

	const fpSize = 32

	var (
		a  [2]*big.Int
		b  [2][2]*big.Int
		c  [2]*big.Int
		pi [2]*big.Int
	)

	// proof.Ar, proof.Bs, proof.Krs
	a[0] = new(big.Int).SetBytes(proofBytes[fpSize*0 : fpSize*1])
	a[1] = new(big.Int).SetBytes(proofBytes[fpSize*1 : fpSize*2])
	b[0][0] = new(big.Int).SetBytes(proofBytes[fpSize*2 : fpSize*3])
	b[0][1] = new(big.Int).SetBytes(proofBytes[fpSize*3 : fpSize*4])
	b[1][0] = new(big.Int).SetBytes(proofBytes[fpSize*4 : fpSize*5])
	b[1][1] = new(big.Int).SetBytes(proofBytes[fpSize*5 : fpSize*6])
	c[0] = new(big.Int).SetBytes(proofBytes[fpSize*6 : fpSize*7])
	c[1] = new(big.Int).SetBytes(proofBytes[fpSize*7 : fpSize*8])
	pi[0] = new(big.Int).SetBytes(piBytes[fpSize*0 : fpSize*1])
	pi[1] = new(big.Int).SetBytes(piBytes[fpSize*1 : fpSize*2])

	println("a[0] is ", a[0].String())
	println("a[1] is ", a[1].String())

	println("b[0][0] is ", b[0][0].String())
	println("b[0][1] is ", b[0][1].String())
	println("b[1][0] is ", b[1][0].String())
	println("b[1][1] is ", b[1][1].String())

	println("c[0] is ", c[0].String())
	println("c[1] is ", c[1].String())

	println("pi[0] is ", pi[0].String())
	println("pi[1] is ", pi[1].String())

	fmt.Println("proof:", hex.EncodeToString(proofBytes))
	fmt.Println("public inputs:", hex.EncodeToString(piBytes))
	fmt.Println("vk", hex.EncodeToString(vkBytes))

  return C.CString(hex.EncodeToString(proofBytes))
}

func main() {
  // cStr := C.CString("../testdata")
	// GenerateGroth16Proof(cStr)
  // defer C.free(unsafe.Pointer(cStr))
}
