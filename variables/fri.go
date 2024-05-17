package variables

import (
	gl "github.com/zilong-dai/gnark-plonky2-verifier/goldilocks"
	"github.com/zilong-dai/gnark-plonky2-verifier/poseidon"
)

type PolynomialCoeffs struct {
	Coeffs []gl.QuadraticExtensionVariable
}

func NewPolynomialCoeffs(numCoeffs uint64) PolynomialCoeffs {
	return PolynomialCoeffs{Coeffs: make([]gl.QuadraticExtensionVariable, numCoeffs)}
}

type FriMerkleCap = []poseidon.BLS12381HashOut

func NewFriMerkleCap(capHeight uint64) FriMerkleCap {
	return make([]poseidon.BLS12381HashOut, 1<<capHeight)
}

type FriMerkleProof struct {
	Siblings []poseidon.BLS12381HashOut // Length = CircuitConfig.FriConfig.DegreeBits + CircuitConfig.FriConfig.RateBits - CircuitConfig.FriConfig.CapHeight
}

func NewFriMerkleProof(merkleProofLen uint64) FriMerkleProof {
	return FriMerkleProof{Siblings: make([]poseidon.BLS12381HashOut, merkleProofLen)}
}

type FriEvalProof struct {
	Elements    []gl.Variable // Length = [CommonCircuitData.Constants + CommonCircuitData.NumRoutedWires, CommonCircuitData.NumWires + CommonCircuitData.FriParams.Hiding ? 4 : 0, CommonCircuitData.NumChallenges * (1 + CommonCircuitData.NumPartialProducts) + salt, CommonCircuitData.NumChallenges * CommonCircuitData.QuotientDegreeFactor + salt]
	MerkleProof FriMerkleProof
}

func NewFriEvalProof(elements []gl.Variable, merkleProof FriMerkleProof) FriEvalProof {
	return FriEvalProof{Elements: elements, MerkleProof: merkleProof}
}

type FriInitialTreeProof struct {
	EvalsProofs []FriEvalProof // Length = 4
}

func NewFriInitialTreeProof(evalsProofs []FriEvalProof) FriInitialTreeProof {
	return FriInitialTreeProof{EvalsProofs: evalsProofs}
}

type FriQueryStep struct {
	Evals       []gl.QuadraticExtensionVariable // Length = [2^arityBit for arityBit in CommonCircuitData.FriParams.ReductionArityBits]
	MerkleProof FriMerkleProof                  // Length = [regularSize - arityBit for arityBit in CommonCircuitData.FriParams.ReductionArityBits]
}

func NewFriQueryStep(arityBit uint64, merkleProofLen uint64) FriQueryStep {
	return FriQueryStep{
		Evals:       make([]gl.QuadraticExtensionVariable, 1<<arityBit),
		MerkleProof: NewFriMerkleProof(merkleProofLen),
	}
}

type FriQueryRound struct {
	InitialTreesProof FriInitialTreeProof
	Steps             []FriQueryStep // Length = Len(CommonCircuitData.FriParams.ReductionArityBits)
}

func NewFriQueryRound(steps []FriQueryStep, initialTreesProof FriInitialTreeProof) FriQueryRound {
	return FriQueryRound{InitialTreesProof: initialTreesProof, Steps: steps}
}

type FriProof struct {
	CommitPhaseMerkleCaps []FriMerkleCap  // Length = Len(CommonCircuitData.FriParams.ReductionArityBits)
	QueryRoundProofs      []FriQueryRound // Length = CommonCircuitData.FriConfig.FriParams.NumQueryRounds
	FinalPoly             PolynomialCoeffs
	PowWitness            gl.Variable
}

type FriChallenges struct {
	FriAlpha        gl.QuadraticExtensionVariable
	FriBetas        []gl.QuadraticExtensionVariable
	FriPowResponse  gl.Variable
	FriQueryIndices []gl.Variable
}
