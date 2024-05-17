package trusted_setup

import (
	"log"
	"os"

	"github.com/GopherJ/gnark-ignition-verifier/ignition"
	bls12381 "github.com/consensys/gnark-crypto/ecc/bls12-381"
	"github.com/consensys/gnark-crypto/ecc/bls12-381/fr"
	kzg_bls12_381 "github.com/consensys/gnark-crypto/ecc/bls12-381/kzg"
)

func sanityCheck(srs *kzg_bls12_381.SRS) {
	// we can now use the SRS to verify a proof
	// create a polynomial
	f := randomPolynomial(60)

	// commit the polynomial
	digest, err := kzg_bls12_381.Commit(f, srs.Pk)
	if err != nil {
		log.Fatal(err)
	}

	// compute opening proof at a random point
	var point fr.Element
	point.SetString("4321")
	proof, err := kzg_bls12_381.Open(f, point, srs.Pk)
	if err != nil {
		log.Fatal(err)
	}

	// verify the claimed valued
	expected := eval(f, point)
	if !proof.ClaimedValue.Equal(&expected) {
		log.Fatal("inconsistent claimed value")
	}

	// verify correct proof
	err = kzg_bls12_381.Verify(&digest, &proof, point, srs.Vk)
	if err != nil {
		log.Fatal(err)
	}
}

func randomPolynomial(size int) []fr.Element {
	f := make([]fr.Element, size)
	for i := 0; i < size; i++ {
		f[i].SetRandom()
	}
	return f
}

// eval returns p(point) where p is interpreted as a polynomial
// ∑_{i<len(p)}p[i]Xⁱ
func eval(p []fr.Element, point fr.Element) fr.Element {
	var res fr.Element
	n := len(p)
	res.Set(&p[n-1])
	for i := n - 2; i >= 0; i-- {
		res.Mul(&res, &point).Add(&res, &p[i])
	}
	return res
}

func DownloadAndSaveAztecIgnitionSrs(startIdx int, fileName string) {
	config := ignition.Config{
		BaseURL:  "https://aztec-ignition.s3.amazonaws.com/",
		Ceremony: "MAIN IGNITION", // "TINY_TEST_5"
		CacheDir: "./data",
	}

	if config.CacheDir != "" {
		err := os.MkdirAll(config.CacheDir, os.ModePerm)

		if err != nil {
			log.Fatal("when creating cache dir: ", err)
			panic(err)
		}
	}

	log.Println("fetch manifest")

	manifest, err := ignition.NewManifest(config)

	if err != nil {
		log.Fatal("when fetching manifest: ", err)
	}

	current, next := ignition.NewContribution(manifest.NumG1Points), ignition.NewContribution(manifest.NumG1Points)

	if err := current.Get(manifest.Participants[startIdx], config); err != nil {
		log.Fatal("when fetching contribution: ", err)
	}
	if err := next.Get(manifest.Participants[startIdx+1], config); err != nil {
		log.Fatal("when fetching contribution: ", err)
	}
	if !next.Follows(&current) {
		log.Fatalf("contribution %d does not follow contribution %d", startIdx+1, startIdx)
	}

	for i := startIdx + 2; i < len(manifest.Participants); i++ {
		log.Println("processing contribution ", i+1)
		current, next = next, current
		if err := next.Get(manifest.Participants[i], config); err != nil {
			log.Fatal("when fetching contribution ", i+1, ": ", err)
		}
		if !next.Follows(&current) {
			log.Fatal("contribution ", i+1, " does not follow contribution ", i, ": ", err)
		}
	}

	log.Println("success ✅: all contributions are valid")

	_, _, _, g2gen := bls12381.Generators()
	// we use the last contribution to build a kzg SRS for bls12381
	srs := kzg_bls12_381.SRS{
		Pk: kzg_bls12_381.ProvingKey{
			G1: next.G1,
		},
		Vk: kzg_bls12_381.VerifyingKey{
			G1: next.G1[0],
			G2: [2]bls12381.G2Affine{
				g2gen,
				next.G2[0],
			},
		},
	}

	// sanity check
	sanityCheck(&srs)
	log.Println("success ✅: kzg sanity check with SRS")

	fSRS, err := os.Create(fileName)
	if err != nil {
		log.Fatal("error creating srs file: ", err)
		panic(err)
	}
	defer fSRS.Close()

	_, err = srs.WriteTo(fSRS)
	if err != nil {
		log.Fatal("error writing srs file: ", err)
		panic(err)
	}
}
