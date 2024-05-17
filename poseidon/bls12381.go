package poseidon

// This is a customized implementation of the Poseidon hash function inside the BLS12381 field.
// This implementation is based on the following implementation:
//
// 		https://github.com/iden3/go-iden3-crypto/blob/master/poseidon/poseidon.go
//
// The input and output are modified to ingest Goldilocks field elements.

import (
	"math/big"

	bls12381 "github.com/consensys/gnark-crypto/ecc/bls12-381"
	gl "github.com/zilong-dai/gnark-plonky2-verifier/goldilocks"
	"github.com/zilong-dai/gnark/frontend"
)

const BLS12381_FULL_ROUNDS int = 8
const BLS12381_PARTIAL_ROUNDS int = 56
const BLS12381_SPONGE_WIDTH int = 4
const BLS12381_SPONGE_RATE int = 3

type BLS12381Chip struct {
	api frontend.API `gnark:"-"`
	gl  *gl.Chip     `gnark:"-"`
}

type BLS12381State = [BLS12381_SPONGE_WIDTH]frontend.Variable
type BLS12381HashOut = frontend.Variable

func NewBLS12381Chip(api frontend.API) *BLS12381Chip {
	if api.Compiler().Field().Cmp(bls12381.ID.ScalarField()) != 0 {
		panic("Gnark compiler not set to BLS12381 scalar field")
	}

	return &BLS12381Chip{api: api, gl: gl.New(api)}
}

func (c *BLS12381Chip) Poseidon(state BLS12381State) BLS12381State {
	state = c.ark(state, 0)
	state = c.fullRounds(state, true)
	state = c.partialRounds(state)
	state = c.fullRounds(state, false)
	return state
}

func (c *BLS12381Chip) HashNoPad(input []gl.Variable) BLS12381HashOut {
	state := BLS12381State{
		frontend.Variable(0),
		frontend.Variable(0),
		frontend.Variable(0),
		frontend.Variable(0),
	}

	two_to_32 := new(big.Int).SetInt64(1 << 32)
	two_to_64 := new(big.Int).Mul(two_to_32, two_to_32)

	for i := 0; i < len(input); i += BLS12381_SPONGE_RATE * 3 {
		endI := c.min(len(input), i+BLS12381_SPONGE_RATE*3)
		rateChunk := input[i:endI]
		for j, stateIdx := 0, 0; j < len(rateChunk); j, stateIdx = j+3, stateIdx+1 {
			endJ := c.min(len(rateChunk), j+3)
			bls12381Chunk := rateChunk[j:endJ]

			inter := frontend.Variable(0)
			for k := 0; k < len(bls12381Chunk); k++ {
				inter = c.api.MulAcc(inter, bls12381Chunk[k].Limb, new(big.Int).Exp(two_to_64, big.NewInt(int64(k)), nil))
			}

			state[stateIdx+1] = inter
		}

		state = c.Poseidon(state)
	}

	return BLS12381HashOut(state[0])
}

func (c *BLS12381Chip) HashOrNoop(input []gl.Variable) BLS12381HashOut {
	if len(input) <= 3 {
		returnVal := frontend.Variable(0)

		alpha := new(big.Int).SetInt64(1 << 32)
		alpha = new(big.Int).Mul(alpha, alpha)
		for i, inputElement := range input {
			mulFactor := new(big.Int).Exp(alpha, big.NewInt(int64(i)), nil)
			returnVal = c.api.MulAcc(returnVal, inputElement.Limb, mulFactor)
		}

		return BLS12381HashOut(returnVal)
	} else {
		return c.HashNoPad(input)
	}
}

func (c *BLS12381Chip) TwoToOne(left BLS12381HashOut, right BLS12381HashOut) BLS12381HashOut {
	var inputs BLS12381State
	inputs[0] = frontend.Variable(0)
	inputs[1] = frontend.Variable(0)
	inputs[2] = left
	inputs[3] = right
	state := c.Poseidon(inputs)
	return state[0]
}

func (c *BLS12381Chip) ToVec(hash BLS12381HashOut) []gl.Variable {
	bits := c.api.ToBinary(hash)

	returnElements := []gl.Variable{}

	// Split into 7 byte chunks, since 8 byte chunks can result in collisions
	chunkSize := 56
	for i := 0; i < len(bits); i += chunkSize {
		maxIdx := c.min(len(bits), i+chunkSize)
		bitChunk := bits[i:maxIdx]
		returnElements = append(returnElements, gl.NewVariable(c.api.FromBinary(bitChunk...)))
	}

	return returnElements
}

func (c *BLS12381Chip) min(x, y int) int {
	if x < y {
		return x
	}

	return y
}

func (c *BLS12381Chip) fullRounds(state BLS12381State, isFirst bool) BLS12381State {
	for i := 0; i < BLS12381_FULL_ROUNDS/2-1; i++ {
		state = c.exp5state(state)
		if isFirst {
			state = c.ark(state, (i+1)*BLS12381_SPONGE_WIDTH)
		} else {
			state = c.ark(state, (BLS12381_FULL_ROUNDS/2+1)*BLS12381_SPONGE_WIDTH+BLS12381_PARTIAL_ROUNDS+i*BLS12381_SPONGE_WIDTH)
		}
		state = c.mix(state, mMatrix)
	}

	state = c.exp5state(state)
	if isFirst {
		state = c.ark(state, (BLS12381_FULL_ROUNDS/2)*BLS12381_SPONGE_WIDTH)
		state = c.mix(state, pMatrix)
	} else {
		state = c.mix(state, mMatrix)
	}

	return state
}

func (c *BLS12381Chip) partialRounds(state BLS12381State) BLS12381State {
	for i := 0; i < BLS12381_PARTIAL_ROUNDS; i++ {
		state[0] = c.exp5(state[0])
		state[0] = c.api.Add(state[0], cConstants[(BLS12381_FULL_ROUNDS/2+1)*BLS12381_SPONGE_WIDTH+i])

		newState0 := frontend.Variable(0)
		for j := 0; j < BLS12381_SPONGE_WIDTH; j++ {
			newState0 = c.api.MulAcc(newState0, sConstants[(BLS12381_SPONGE_WIDTH*2-1)*i+j], state[j])
		}

		for k := 1; k < BLS12381_SPONGE_WIDTH; k++ {
			state[k] = c.api.MulAcc(state[k], state[0], sConstants[(BLS12381_SPONGE_WIDTH*2-1)*i+BLS12381_SPONGE_WIDTH+k-1])
		}
		state[0] = newState0
	}

	return state
}

func (c *BLS12381Chip) ark(state BLS12381State, it int) BLS12381State {
	var result BLS12381State

	for i := 0; i < len(state); i++ {
		result[i] = c.api.Add(state[i], cConstants[it+i])
	}

	return result
}

func (c *BLS12381Chip) exp5(x frontend.Variable) frontend.Variable {
	x2 := c.api.Mul(x, x)
	x4 := c.api.Mul(x2, x2)
	return c.api.Mul(x4, x)
}

func (c *BLS12381Chip) exp5state(state BLS12381State) BLS12381State {
	for i := 0; i < BLS12381_SPONGE_WIDTH; i++ {
		state[i] = c.exp5(state[i])
	}
	return state
}

func (c *BLS12381Chip) mix(state_ BLS12381State, constantMatrix [][]*big.Int) BLS12381State {
	var result BLS12381State

	for i := 0; i < BLS12381_SPONGE_WIDTH; i++ {
		result[i] = frontend.Variable(0)
	}

	for i := 0; i < BLS12381_SPONGE_WIDTH; i++ {
		for j := 0; j < BLS12381_SPONGE_WIDTH; j++ {
			result[i] = c.api.MulAcc(result[i], constantMatrix[j][i], state_[j])
		}
	}

	return result
}
