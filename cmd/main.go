package main

/*
#include <stdlib.h> // Include C standard library, if necessary
#include <string.h>
typedef struct {
    char* proof;
    char* vk;
} Groth16ProofWithVK;
*/
import "C"
import (
	"fmt"
	"os"

	"github.com/cf/gnark-plonky2-verifier/worker"
)

type Groth16ProofWithVK struct {
  Proof string
  Vk string
}

//export GenerateGroth16Proof
func GenerateGroth16Proof(common_circuit_data *C.char, proof_with_public_inputs *C.char, verifier_only_circuit_data *C.char, keystore_path *C.char) *C.Groth16ProofWithVK {
  proof_str, vk_str := worker.GenerateProof(C.GoString(common_circuit_data), C.GoString(proof_with_public_inputs), C.GoString(verifier_only_circuit_data), C.GoString(keystore_path))

  cProofWithVk := (*C.Groth16ProofWithVK)(C.malloc(C.sizeof_Groth16ProofWithVK))
  cProofWithVk.proof = C.CString(proof_str)
  cProofWithVk.vk = C.CString(vk_str)
	return cProofWithVk
}

//export VerifyGroth16Proof
func VerifyGroth16Proof(proofString *C.char, vkString *C.char) *C.char {
	return C.CString(worker.VerifyProof(C.GoString(proofString), C.GoString(vkString)))
}

func main() {
	fmt.Println(worker.VerifyProof(
    "{\"CommitmentPok\":\"400000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000\",\"Commitments\":\"\",\"pi_a\":[\"0793476af4568eb8a96a6b8a7bccb79daa767128de5fc6b357a4129ae8d1f68f8c74af85f46117c74dd0e8fc01b2f3b9\",\"148472df9b4843764e675bdcd13cedd96a2f10f7b749659c74363ddefe56515c1fbefdff5450d4671c46aaa5326be771\"],\"pi_b\":[[\"19994cc6cb6540d912ad4a49919c263d5e6979a0e652e804c4b44a43d65db57926f8cac4a78dbd039e155b7726a4a718\",\"070958f07d9a3ee6da0355b38049c2e135d6e4d8d58717bd75bbbc609785c80fcf62cacb4f19f8b9579f8476fcfadda7\"],[\"169017f38052c1890fa861dae71e8a2095a352a645fee9a6a744f77aa91dc27c15c10f068c6c44a7862ec6e48c62780b\",\"1543f39975b8318853175e16d1f243930db3123d5f74b04298ae319b130b32d7ffd82636b337a72f9034f381d810f33e\"]],\"pi_c\":[\"0457f65a1a467b1edab58db046b3ef2f9367bd5bc631faea8af5b2b57772cee6d27e87b91fed28e84792f7bf641aecb0\",\"14cdee203d5ed357813c37a72b3b0a64532e38ec8753fac4c1b93e8291c3c5c4f7d365e556401d70e83b9e21e0086418\"],\"public_inputs\":[\"5b7c872867ddad7a71e3ee2f730a2c7b38276da86f1a9807673cabdcbe89ecca\",\"0d680fa6b31d7f87f9b505d3b42b14b5c8f41cff8e19c51095cb3cd98abca1a4\"]}",
    "{\"CommitmentKey\":\"120aeea7669f3e488b05b65d76862ee78d0737f3a6bdeb3f0c24b77747e8675565a89c2e6bf013cd4390b5b274ba634c0f5b115f62064164037c30948baace9ed5437b2772e1f78541601ab59c3318b15f50010f564df7a03d238267b3c08df2081a8c4f74a2ad1a63369edf890ce207b5a5c86cee6838c8178958b744c34743e60ead4adb2ba3c11490392bdb7ee0840fba81035d99404a7a2aa21910742163f15ef7e654f55b64b2b0750781319ce040801ffe2cf1c0bcda6a31723a0f46a11096c4dfaea70d4f9edc44873f97f574cb39c38599199796e0a45eb68c0d365171cccdb9e3a0e528e509abece517d034068f671d85c2ca287865ef9f74e442258624122dd2f92c83872661c7983df0ee2ab1185eef9bd933aac7ea3a620753cf0aadee61fa7afc6ceabff71d9659adfe1a1259c10e8e45e634b1fdeb49229cfd87f4d3d7b34f86258902d3ab96fc2826150d1e833f09c5d7e681384b26b3448becc7db8b935a121523a584f61fcb43d51c267488bf534607fbbcaf50c3cee175\",\"PublicAndCommitmentCommitted\":[],\"alpha_g1\":[\"0ad422b5407803f6e3c3d92d3f628d44d66378a59fb254b5cda1fdbc11c9d6023e59276fffe3a5106d341e59e41443b1\",\"02402240d1a6c66d0b6487d23fae9d143cdd8526a82671a828a683e96973e7b3fa6ec708067afb4a90dd923fec66721b\"],\"beta_g2\":[[\"155571e3364bbb2e80ff18b56df3aa6dc9119c9395d2cae57c9a84c3c972d650b5d9aae0eb3aa800509059689c94c9c0\",\"063e38f518464ccf1c2eac558dc2d97737e08f2cea0b2f9bd56be56338bfdbf27db4885179edce4ab6f29273ee89a96a\"],[\"14bb7d161669fa6ddd2fa432b977178108673c0e64628169390796412e310f9053041fa466ca881ded208710dd05a1aa\",\"136f342a58451cc67779045b7d6d17203f81232cb95af26b66a9f0be36549041d67f8246eb0f4508e73951dd277f6eaf\"]],\"delta_g2\":[[\"19daceb48d1ac525e9c0380f7de79119e180100de0b7c5207ef959d90e99e580aa2ef63eee442e53874d4a1edae7da2f\",\"0571cbd36021fa7e0614de427d8f6decb71a24d285afa21375ec49436956bf6ec3fae66acbbee847d77fcb39ec905a08\"],[\"0e42c5b1bfdd558bf3ac72f8f61b9cb940b4b90a902274b64309d9448f03cd97f8f7e2f26ce5e90bfb37de5117869b02\",\"15ab68e0ef7723076b6ec8744ae1fb778b73a3c63bcf886e84588f058ad3881a4301b6f561c6aef65aaa9bb2ae603190\"]],\"gamma_abc_g1\":[[\"0a337073e0f2d28a191eaa750680069c72ed228edd3951abfd7cd34877ce4a8d5e267ea0d8f2232c5b27f24fa7927e4c\",\"02e393ba1c374ccccb59b3fe3d8b52f003d4cdb129bdd7fb03e8cdf67a75c2fb7810985a703fedc5392da49662ad1909\"],[\"0b41b538fb82bc54416dec2ce5e71aa0af970b23cb09d3d7a18b6f0978d938f17c98b3829af05529e95665788f9168d7\",\"123a5a1b1fc7b78e183333e18882a82207e6cb823b8911f0e1a4de633df35813d70cc700ca0f87bb5d7b8718066bc7c5\"],[\"0feae63a1d44377df8fcfdc68bc5eeb68bb0a8f3d10329d02f0bf2fd59aa39dd2da64c904c290bb751b19d307b7c84c0\",\"13ac493de618bc21ee76738a159a8c75452d5f47d4652b09c30b67bbe1521bd54856c2e2b37d0cff5c193a50c8221721\"]],\"gamma_g2\":[[\"0372d175619a3be8cf181bd6828fecdc69d9c0b7d4a1f9ef3f33f059b105887d6404fdf153bc64cbddb8c37844048893\",\"0532a637bd7c043a9078f257b35bb4cd810970a85a198aba9b82e20fdb4cd421dea2b5d555fe3ed79918f6261b3394b3\"],[\"165843da299ba4114457b9b0e8375f5e3c16907caff5ab15ff0282f4521478f4a206aba0950ee279d93e86212a0d5563\",\"0618a0e6e8797ec8212f675554c91089d573f327ba229256836af7d305cd0d7a96fe225e591d6384881b034f98be5421\"]]}"))

  path := "/tmp/plonky2_proof/0"

	common_circuit_data, _ := os.ReadFile(path + "/common_circuit_data.json")

	proof_with_public_inputs, _ := os.ReadFile(path + "/proof_with_public_inputs.json")

	verifier_only_circuit_data, _ := os.ReadFile(path + "/verifier_only_circuit_data.json")

  proof_city, vk_city := worker.GenerateProof(string(common_circuit_data), string(proof_with_public_inputs), string(verifier_only_circuit_data), "/tmp/groth16-keystore/0/")
  fmt.Println("proof city", proof_city)
  fmt.Println("vk city", vk_city)
}
