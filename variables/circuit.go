package variables

import (
	gl "github.com/zilong-dai/gnark-plonky2-verifier/goldilocks"
	"github.com/zilong-dai/gnark-plonky2-verifier/poseidon"
)

type Proof struct {
	WiresCap                  FriMerkleCap // length = 2^CircuitConfig.FriConfig.CapHeight
	PlonkZsPartialProductsCap FriMerkleCap // length = 2^CircuitConfig.FriConfig.CapHeight
	QuotientPolysCap          FriMerkleCap // length = 2^CircuitConfig.FriConfig.CapHeight
	Openings                  OpeningSet
	OpeningProof              FriProof
}

type ProofWithPublicInputs struct {
	Proof        Proof
	PublicInputs []gl.Variable // Length = CommonCircuitData.NumPublicInputs
}

type VerifierOnlyCircuitData struct {
	ConstantSigmasCap FriMerkleCap
	CircuitDigest     poseidon.BLS12381HashOut
}
