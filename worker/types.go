package worker

import (
	"bytes"
	"encoding/hex"
	"encoding/json"

	"github.com/consensys/gnark-crypto/ecc"
	curve "github.com/consensys/gnark-crypto/ecc/bls12-381"
	bls12381 "github.com/consensys/gnark/backend/groth16/bls12-381"
	"github.com/consensys/gnark/backend/witness"
)

const CURVE_ID = ecc.BLS12_381
const KEY_STORE_PATH = "/tmp/groth16-keystore/"

var CIRCUIT_PATH string = "circuit_groth16.bin"
var VK_PATH string = "vk_groth16.bin"
var PK_PATH string = "pk_groth16.bin"
var PROOF_PATH string = "proof_groth16.bin"
var WITNESS_PATH string = "witness_groth16.bin"

type G16ProofWithPublicInputs struct {
	Proof        bls12381.Proof
	PublicInputs witness.Witness
}

func Chunk(str string, chunk int) []string {
	if len(str) < chunk*96 {
		panic("proof field element string too short")
	}
	res := make([]string, chunk)

	// chunkSize := len(str) / chunk

	for i := 0; i < chunk; i++ {
		res[i] = str[i*96 : (i+1)*96]
	}

	return res
}

func (p G16ProofWithPublicInputs) MarshalJSON() ([]byte, error) {

	proof := p.Proof

	var buf [48 * 2]byte
	var writer bytes.Buffer

	for i := 0; i < len(proof.Commitments); i++ {
		buf = proof.Commitments[i].RawBytes()
		_, err := writer.Write(buf[:])
		if err != nil {
			return nil, err
		}
	}

	pi_a_arr := Chunk(hex.EncodeToString((&proof.Ar).Marshal()), 2)
	pi_b_arr := Chunk(hex.EncodeToString((&proof.Bs).Marshal()), 4)
	pi_c_arr := Chunk(hex.EncodeToString((&proof.Krs).Marshal()), 2)

	var buffer bytes.Buffer
	_, err := p.PublicInputs.WriteTo(&buffer)
	if err != nil {
		panic(err)
	}
	public_inputs_arr := hex.EncodeToString(buffer.Bytes())[24:]

	proof_map := map[string]interface{}{
		"pi_a":           [2]string{pi_a_arr[0], pi_a_arr[1]},
		"pi_b":           [2][2]string{{pi_b_arr[0], pi_b_arr[1]}, {pi_b_arr[2], pi_b_arr[3]}},
		"pi_c":           [2]string{pi_c_arr[0], pi_c_arr[1]},
		"Commitments":    hex.EncodeToString(writer.Bytes()),
		"CommitmentPok":  hex.EncodeToString((&proof.CommitmentPok).Marshal()),
		"public_inputs": [2]string{public_inputs_arr[0:64], public_inputs_arr[64:128]},
	}
	return json.Marshal(proof_map)

}

func NewG16ProofWithPublicInputs(curveId ecc.ID) *G16ProofWithPublicInputs {

	var proof bls12381.Proof

	publicInputs, err := witness.New(curveId.ScalarField())
	if err != nil {
		panic(err)
	}

	return &G16ProofWithPublicInputs{
		Proof:        proof,
		PublicInputs: publicInputs,
	}

}

func (p *G16ProofWithPublicInputs) UnmarshalJSON(data []byte) error {

	var ProofString struct {
		PiA           [2]string    `json:"pi_a"`
		PiB           [2][2]string `json:"pi_b"`
		PiC           [2]string    `json:"pi_c"`
		Commitments   string       `json:"Commitments"`
		CommitmentPok string       `json:"CommitmentPok"`
		PublicInputs  [2]string    `json:"public_inputs"`
	}

	err := json.Unmarshal(data, &ProofString)
	if err != nil {
		return err
	}

	pia_bytes, err := hex.DecodeString(ProofString.PiA[0] + ProofString.PiA[1])
	if err != nil {
		return err
	}
	err = p.Proof.Ar.Unmarshal(pia_bytes)
	if err != nil {
		return err
	}

	pib_bytes, err := hex.DecodeString(ProofString.PiB[0][0] + ProofString.PiB[0][1] + ProofString.PiB[1][0] + ProofString.PiB[1][1])
	if err != nil {
		return err
	}
	err = p.Proof.Bs.Unmarshal(pib_bytes)
	if err != nil {
		return err
	}

	pic_bytes, err := hex.DecodeString(ProofString.PiC[0] + ProofString.PiC[1])
	if err != nil {
		return err
	}
	err = p.Proof.Krs.Unmarshal(pic_bytes)
	if err != nil {
		return err
	}

	com_bytes, err := hex.DecodeString(ProofString.Commitments)
	if err != nil {
		return err
	}
	len := len(com_bytes) / 96
	p.Proof.Commitments = make([]curve.G1Affine, len)
	for i := 0; i < len; i++ {
		err = p.Proof.Commitments[i].Unmarshal(com_bytes[96*i : 96*(i+1)])
		if err != nil {
			return err
		}
	}

	compok_bytes, err := hex.DecodeString(ProofString.CommitmentPok)
	if err != nil {
		return err
	}
	err = p.Proof.CommitmentPok.Unmarshal(compok_bytes)
	if err != nil {
		return err
	}

	// public inputs num 2, witness inputs num 0, vector length 2
	publicinputs_bytes, err := hex.DecodeString("000000020000000000000002" + ProofString.PublicInputs[0] + ProofString.PublicInputs[1])

	if err != nil {
		return err
	}

	reader := bytes.NewReader(publicinputs_bytes)

	if _, err = p.PublicInputs.ReadFrom(reader); err != nil {
		return err
	}

	return nil
}
