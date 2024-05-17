package verifier_test

import (
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/zilong-dai/gnark-plonky2-verifier/types"
	"github.com/zilong-dai/gnark-plonky2-verifier/variables"
	"github.com/zilong-dai/gnark-plonky2-verifier/verifier"
	"github.com/zilong-dai/gnark/test"
)

func TestStepVerifier(t *testing.T) {
	assert := test.NewAssert(t)

	testCase := func() {
		plonky2Circuit := ""
		commonCircuitData := types.ReadCommonCircuitData("../testdata/" + plonky2Circuit + "/common_circuit_data.json")

		proofWithPis := variables.DeserializeProofWithPublicInputs(types.ReadProofWithPublicInputs("../testdata/" + plonky2Circuit + "/proof_with_public_inputs.json"))
		verifierOnlyCircuitData := variables.DeserializeVerifierOnlyCircuitData(types.ReadVerifierOnlyCircuitData("../testdata/" + plonky2Circuit + "/verifier_only_circuit_data.json"))

		circuit := verifier.ExampleVerifierCircuit{
			Proof:                   proofWithPis.Proof,
			PublicInputs:            proofWithPis.PublicInputs,
			VerifierOnlyCircuitData: verifierOnlyCircuitData,
			CommonCircuitData:       commonCircuitData,
		}

		witness := verifier.ExampleVerifierCircuit{
			Proof:                   proofWithPis.Proof,
			PublicInputs:            proofWithPis.PublicInputs,
			VerifierOnlyCircuitData: verifierOnlyCircuitData,
			CommonCircuitData:       commonCircuitData,
		}

		err := test.IsSolved(&circuit, &witness, ecc.BLS12_381.ScalarField())
		assert.NoError(err)
	}
	testCase()
}
