package worker

import (
	"bytes"
	"encoding/json"
	"math/big"
	"os"

	gl "github.com/cf/gnark-plonky2-verifier/goldilocks"
	"github.com/cf/gnark-plonky2-verifier/types"
	"github.com/cf/gnark-plonky2-verifier/variables"
	"github.com/cf/gnark-plonky2-verifier/verifier"
	"github.com/consensys/gnark/backend/groth16"
	bls12381 "github.com/consensys/gnark/backend/groth16/bls12-381"
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
	if len(c.OriginalPublicInputs) != 512 {
		panic("invalid original public inputs, should contain 512 goldilocks elements")
	}

	two := big.NewInt(2)

	blockStateHashAcc := frontend.Variable(0)
	sighashAcc := frontend.Variable(0)
	for i := 255; i >= 0; i-- {
		blockStateHashAcc = api.MulAcc(c.OriginalPublicInputs[i].Limb, blockStateHashAcc, two)
	}
	for i := 511; i >= 256; i-- {
		sighashAcc = api.MulAcc(c.OriginalPublicInputs[i].Limb, sighashAcc, two)
	}

	api.AssertIsEqual(c.PublicInputs[0], blockStateHashAcc)
	api.AssertIsEqual(c.PublicInputs[1], sighashAcc)

	verifierChip.Verify(c.Proof, c.OriginalPublicInputs, c.VerifierOnlyCircuitData)

	return nil
}

func initKeyStorePath() {
	_, err := os.Stat(KEY_STORE_PATH)
	if err != nil {
		if os.IsNotExist(err) {
			os.MkdirAll(KEY_STORE_PATH, os.ModePerm)
		}
	}
}

func GenerateProof(common_circuit_data string, proof_with_public_inputs string, verifier_only_circuit_data string) string {
	initKeyStorePath()
	commonCircuitData := types.ReadCommonCircuitDataRaw(common_circuit_data)

	verifierOnlyCircuitData := variables.DeserializeVerifierOnlyCircuitData(types.ReadVerifierOnlyCircuitDataRaw(verifier_only_circuit_data))

	rawProofWithPis := types.ReadProofWithPublicInputsRaw(proof_with_public_inputs)
	proofWithPis := variables.DeserializeProofWithPublicInputs(rawProofWithPis)

	two := big.NewInt(2)

	blockStateHashAcc := big.NewInt(0)
	sighashAcc := big.NewInt(0)
	for i := 255; i >= 0; i-- {
		blockStateHashAcc = new(big.Int).Mul(blockStateHashAcc, two)
		blockStateHashAcc = new(big.Int).Add(blockStateHashAcc, new(big.Int).SetUint64(rawProofWithPis.PublicInputs[i]))
	}
	for i := 511; i >= 256; i-- {
		sighashAcc = new(big.Int).Mul(sighashAcc, two)
		sighashAcc = new(big.Int).Add(sighashAcc, new(big.Int).SetUint64(rawProofWithPis.PublicInputs[i]))
	}
	blockStateHash := frontend.Variable(blockStateHashAcc)
	sighash := frontend.Variable(sighashAcc)

	circuit := CRVerifierCircuit{
		PublicInputs:            []frontend.Variable{blockStateHash, sighash},
		Proof:                   proofWithPis.Proof,
		OriginalPublicInputs:    proofWithPis.PublicInputs,
		VerifierOnlyCircuitData: verifierOnlyCircuitData,
		CommonCircuitData:       commonCircuitData,
	}

	assignment := CRVerifierCircuit{
		PublicInputs:            circuit.PublicInputs,
		Proof:                   circuit.Proof,
		OriginalPublicInputs:    circuit.OriginalPublicInputs,
		VerifierOnlyCircuitData: circuit.VerifierOnlyCircuitData,
	}

	// NewWitness() must be called before Compile() to avoid gnark panicking.
	// ref: https://github.com/Consensys/gnark/issues/1038
	witness, err := frontend.NewWitness(&assignment, CURVE_ID.ScalarField())
	if err != nil {
		panic(err)
	}

	cs, err := frontend.Compile(CURVE_ID.ScalarField(), r1cs.NewBuilder, &circuit)
	if err != nil {
		panic(err)
	}
	pk, vk, err := groth16.Setup(cs)
	if err != nil {
		panic(err)
	}

	if err := WriteVerifyingKey(vk, KEY_STORE_PATH+VK_PATH); err != nil {
		panic(err)
	}

	if err := WriteProvingKey(pk, KEY_STORE_PATH+PK_PATH); err != nil {
		panic(err)
	}

	proof, err := groth16.Prove(cs, pk, witness)
	if err != nil {
		panic(err)
	}

	publicWitness, err := witness.Public()
	if err != nil {
		panic(err)
	}

	if err := WritePublicInputs(publicWitness, KEY_STORE_PATH+WITNESS_PATH); err != nil {
		panic(err)
	}

	err = groth16.Verify(proof, vk, publicWitness)
	if err != nil {
		panic(err)
	}

	var buffer bytes.Buffer
	if _, err := proof.WriteRawTo(&buffer); err != nil {
		panic(err)
	}

	var blsproof bls12381.Proof
	if _, err := blsproof.ReadFrom(&buffer); err != nil {
		panic(err)
	}

	var g16ProofWithPublicInputs = G16ProofWithPublicInputs{
		Proof:        blsproof,
		PublicInputs: publicWitness,
	}

	proof_bytes, err := json.Marshal(g16ProofWithPublicInputs)
	if err != nil {
		panic(err)
	}

	return string(proof_bytes)

}

func VerifyProof(proofString string) string {
	g16ProofWithPublicInputs := NewG16ProofWithPublicInputs(CURVE_ID)

	if err := json.Unmarshal([]byte(proofString), g16ProofWithPublicInputs); err != nil {
		panic(err)
	}

	vk, err := ReadVerifyingKey(CURVE_ID, KEY_STORE_PATH+VK_PATH)
	if err != nil {
		panic(err)
	}

	if err := groth16.Verify(&g16ProofWithPublicInputs.Proof, vk, g16ProofWithPublicInputs.PublicInputs); err != nil {
		return "false"
	}
	return "true"
}
