package cmd

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/backend/witness"
	"github.com/consensys/gnark/constraint"
)

func WriteProof(proof groth16.Proof, path string) error {
	if proof == nil {
		return fmt.Errorf("proof is not initialized")
	}

	proofFile, err := os.Create(path)
	if err != nil {
		return fmt.Errorf("failed to create file: %w", err)
	}
	defer proofFile.Close()

	if _, err := proof.WriteTo(proofFile); err != nil {
		return fmt.Errorf("failed to write proof to file: %w", err)
	}

	return nil
}

func ReadProof(CURVE_ID ecc.ID, path string) (groth16.Proof, error) {
	proof := groth16.NewProof(CURVE_ID)
	proofFile, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("failed to open proof file: %w", err)
	}
	defer proofFile.Close()

	_, err = proof.ReadFrom(proofFile)
	if err != nil {
		return nil, fmt.Errorf("failed to read proof: %w", err)
	}

	return proof, nil
}

func WritePublicInputs(witness witness.Witness, path string) error {
	if witness == nil {
		return fmt.Errorf("witness is not initialized")
	}

	publicinputsFile, err := os.Create(path)
	if err != nil {
		return fmt.Errorf("failed to create file: %w", err)
	}
	defer publicinputsFile.Close()

	if n, err := witness.WriteTo(publicinputsFile); err != nil {
		fmt.Println(n/32, " witness len ", n)
		return fmt.Errorf("failed to write proof to file: %w", err)
	}

	return nil
}

func ReadPublicInputs(CURVE_ID ecc.ID, path string) (witness.Witness, error) {
	witness, err := witness.New(CURVE_ID.ScalarField())
	if err != nil {
		return nil, fmt.Errorf("failed to create witness: %w", err)
	}

	publicinputsFile, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("failed to open public inputs file: %w", err)
	}
	defer publicinputsFile.Close()

	_, err = witness.ReadFrom(publicinputsFile)
	if err != nil {
		return nil, fmt.Errorf("failed to read public inputs: %w", err)
	}

	return witness, nil
}

func WriteProvingKey(pk groth16.ProvingKey, path string) error {
	if pk == nil {
		return fmt.Errorf("pk is not initialized")
	}

	pkFile, err := os.Create(path)
	if err != nil {
		return fmt.Errorf("failed to create file: %w", err)
	}
	defer pkFile.Close()

	if _, err := pk.WriteRawTo(pkFile); err != nil {
		return fmt.Errorf("failed to write pk to file: %w", err)
	}

	return nil
}

func ReadProvingKey(CURVE_ID ecc.ID, path string) (groth16.ProvingKey, error) {
	pk := groth16.NewProvingKey(CURVE_ID)
	pkFile, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("failed to open pk file: %w", err)
	}
	defer pkFile.Close()

	_, err = pk.ReadFrom(pkFile)
	if err != nil {
		return nil, fmt.Errorf("failed to read pk: %w", err)
	}

	return pk, nil
}

func WriteVerifyingKey(vk groth16.VerifyingKey, path string) error {
	if vk == nil {
		return fmt.Errorf("vk is not initialized")
	}

	vkFile, err := os.Create(path)
	if err != nil {
		return fmt.Errorf("failed to create file: %w", err)
	}
	defer vkFile.Close()

	if _, err := vk.WriteTo(vkFile); err != nil {
		return fmt.Errorf("failed to write vk to file: %w", err)
	}

	return nil
}

func ReadVerifyingKey(CURVE_ID ecc.ID, path string) (groth16.VerifyingKey, error) {
	vk := groth16.NewVerifyingKey(CURVE_ID)
	vkFile, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("failed to open proof file: %w", err)
	}
	defer vkFile.Close()

	_, err = vk.ReadFrom(vkFile)
	if err != nil {
		return nil, fmt.Errorf("failed to read vk: %w", err)
	}

	return vk, nil
}

func ReadCircuit(CURVE_ID ecc.ID, path string) (constraint.ConstraintSystem, error) {
	r1cs := groth16.NewCS(CURVE_ID)
	if r1cs == nil {
		return nil, fmt.Errorf("r1cs is not initialized")
	}

	circuitFile, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("failed to open circuit file: %w", err)
	}
	defer circuitFile.Close()

	_, err = r1cs.ReadFrom(circuitFile)
	if err != nil {
		return nil, fmt.Errorf("failed to read circuit: %w", err)
	}

	return r1cs, nil
}

func WriteCircuit(r1cs constraint.ConstraintSystem, path string) error {
	if r1cs == nil {
		return fmt.Errorf("r1cs is not initialized")
	}

	circuitFile, err := os.Create(path)
	if err != nil {
		return fmt.Errorf("failed to circuit file: %w", err)
	}
	defer circuitFile.Close()

	if _, err := r1cs.WriteTo(circuitFile); err != nil {
		return fmt.Errorf("failed to write circuit to file: %w", err)
	}

	return nil
}

func CheckKeysExist(path string) bool {
	files := []string{
		CIRCUIT_PATH,
		VK_PATH,
		PK_PATH,
	}

	for _, file := range files {
		path := filepath.Join(path, file)
		if _, err := os.Stat(path); err != nil {
			if os.IsNotExist(err) {
				return false
			} else {
				return false
			}
		}
	}

	return true
}

func CheckVKeysExist(path string) bool {

	path = filepath.Join(path, VK_PATH)
	if _, err := os.Stat(path); err != nil {
		if os.IsNotExist(err) {
			return false
		} else {
			return false
		}
	}

	return true
}
