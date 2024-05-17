package poseidon

import (
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	gl "github.com/zilong-dai/gnark-plonky2-verifier/goldilocks"
	"github.com/zilong-dai/gnark/backend"
	"github.com/zilong-dai/gnark/frontend"
	"github.com/zilong-dai/gnark/test"
)

var testCurve = ecc.BLS12_381

type TestPublicInputsHashCircuit struct {
	In  [3]frontend.Variable
	Out [4]frontend.Variable
}

func (circuit *TestPublicInputsHashCircuit) Define(api frontend.API) error {
	glAPI := gl.New(api)

	// BLS12381 -> Binary(64) -> F
	var input [3]gl.Variable
	for i := 0; i < 3; i++ {
		input[i] = gl.NewVariable(api.FromBinary(api.ToBinary(circuit.In[i], 64)...))
	}

	poseidonChip := &GoldilocksChip{api: api, gl: glAPI}
	output := poseidonChip.HashNoPad(input[:])

	// Check that output is correct
	for i := 0; i < 4; i++ {
		glAPI.AssertIsEqual(
			output[i],
			gl.NewVariable(api.FromBinary(api.ToBinary(circuit.Out[i])...)),
		)
	}

	return nil
}

func TestPublicInputsHashWitness(t *testing.T) {
	assert := test.NewAssert(t)

	testCase := func(in [3]frontend.Variable, out [4]frontend.Variable) {
		circuit := TestPublicInputsHashCircuit{In: in, Out: out}
		witness := TestPublicInputsHashCircuit{In: in, Out: out}
		err := test.IsSolved(&circuit, &witness, testCurve.ScalarField())
		assert.NoError(err)
	}

	inStr := []string{"0", "1", "3736710860384812976"}
	outStr := []string{"8416658900775745054", "12574228347150446423", "9629056739760131473", "3119289788404190010"}
	var in [3]frontend.Variable
	var out [4]frontend.Variable
	copy(in[:], gl.StrArrayToFrontendVariableArray(inStr))
	copy(out[:], gl.StrArrayToFrontendVariableArray(outStr))
	testCase(in, out)
}

func TestPublicInputsHashWitness2(t *testing.T) {
	assert := test.NewAssert(t)

	inStr := []string{"0", "1", "3736710860384812976"}
	outStr := []string{"8416658900775745054", "12574228347150446423", "9629056739760131473", "3119289788404190010"}
	var in [3]frontend.Variable
	var out [4]frontend.Variable
	copy(in[:], gl.StrArrayToFrontendVariableArray(inStr))
	copy(out[:], gl.StrArrayToFrontendVariableArray(outStr))

	circuit := TestPublicInputsHashCircuit{In: in, Out: out}
	witness := TestPublicInputsHashCircuit{In: in, Out: out}

	assert.ProverSucceeded(
		&circuit,
		&witness,
		test.WithBackends(backend.GROTH16),
		test.WithCurves(ecc.BLS12_381),
		test.NoFuzzing(),
		test.NoSerializationChecks(),
	)
}
