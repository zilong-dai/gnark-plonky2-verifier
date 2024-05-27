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
	// fmt.Println(worker.VerifyProof(
  //   "{\"CommitmentPok\":\"400000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000\",\"Commitments\":\"\",\"pi_a\":[\"026ebdd3adbf87d2e722e906fe59cb6c01db146fdbd2f595fed1e174b768d2e9f8b13248a1afecb744eb1eff7304cfcf\",\"0d03349809c869ec4a0f24b18dd1052ea0565fc87fc5fd4636919143d06a12d521d9bac0a60a7d1fa28e910f19608d69\"],\"pi_b\":[[\"0b88511326bebee84bb6046819060d43a0a2bed85cc8f3f32cb353c589583469188b505658f8baf604e5d98200107db0\",\"029b070ac219a4610c35b5c7092f93db2c8e0295e6bb34e6fc7847f3e73c09a972d47223092725d89a75f83dba0bd15c\"],[\"16708e37bb0d7fb02006f7da9311a6f24a3cdebea6db564dddd8a9bfee9330f3f768b91d32ecc402411996dde172b561\",\"00a88d2da9f1aa16b381148ea1d11e75a85af20e926d53c332b05c402320e13a734ccc3f5c1ff20b1be6ecea9f09a052\"]],\"pi_c\":[\"0ff565ddae2f69fa27d9445f39393b9cfaf2841f52d9bb38b22b35cb894c62623fcc9d0c08616d7eeffd0993123299a3\",\"0bae5bb72be1893fe7c2d7f98758246f6448701df9d9398f6a626a93823621ebfad37497ff0fa4c935ecabf5d9226fad\"],\"public_inputs\":[\"5b7c872867ddad7a71e3ee2f730a2c7b38276da86f1a9807673cabdcbe89ecca\",\"05c6bd67c785cb62b870aa75050147b992c1ca5120e5f156a0ecce9a7685726a\"]}",
  //   "{\"CommitmentKey\":\"007ec97abb325e70f9186387fb634e7ba7e00356bc9a6f6124ed3fc3d15bb93381b5b134d8fd55ea5c128b0624e6946003a22c509bfc96e95e8de46b8d2a72ff47dcba9816383b2be9c24074cd2506438f32826cc9330b4b9196e26f036731a201d606d43dcd16556144942f210790b8c6446f69081783834ef702f8d52c797fe9fd6bfaeb3ffb580ba46bddf7131f9a05566993bb2f06af6fc0a1d096d1e120f84ef23d3a5cf73052fa53b3d9503e0b0777915dbe5baf6ce5f7f5092f41fb2309e5a8af0a16f71551c21bfe3050e4ded0fb05801cffe3e07ba4d6c3ed53797e064db99c4ee8f9d6ccf5d4a41857d6ee1146d7976c24065ae9cb36dcb1156d80e84cc144280c7d5a4fb8e066faac006286861bffc97834e6c4d3adef21dd2cdf16753603498ec283878f5f7c74b4646dfaec0f6e355865b5a85ba6ecd45267a8e4996aa89d1954eb8c1e4dc33cc3f6460db4ed88a3d36ae52b207a2e2dea7adf28927de9263b3e68bae6c7cca42f87c17731a536f9559c91152d538e35c8235a\",\"PublicAndCommitmentCommitted\":[],\"alpha_g1\":[\"06751e7f5de8c005d395723cb3e1b4b45c561a222c61b08f1f685131744ed961f7e6243177ddd380c4a0bab70bd25c73\",\"058d8dda2d9a1e56ba0035d80c1a4c65b66954ab57a4355227954328f73d8909dce399782206a7031e301cdb89718e8c\"],\"beta_g2\":[[\"0d9d6a1c456a1585ae4f36f39f30998b516b7e6094b723509c4f8a9f7735ac06e1d7a6e430774aa1acc6a00758ed084a\",\"029ab9c16b47edf6e5c61b65584bf480fdb5e02641bcfc57a1a80667ef62bc19aeb0cd8b95ef439dce2323e269286539\"],[\"0dd68ffd4fa993b37757483451d37748abeaecd1a5cf5038bd78167ae1832e0258a1252511fa54e051a9160857ae5dde\",\"0b8cac26322058a43cfd5ef94d2120b6f23aeed8280f2539440c437fd2f15e36eda6b40428dbcfb157f30df002f4a316\"]],\"delta_g2\":[[\"0a060168e1ff7487ad763b9150f1eafce8540414e3ba34138804b6a3391d641c2b4cf9283209e1753a6c9df3e4d701a2\",\"0dab3f0d9a76ff0a5d237b3689db6b8c0203fbd92b0cb18feecf25dd565cf9d7aeed54f2cc1392108344f9897214dd57\"],[\"1476595a0c82c417165925d2c33c9b6c2a59d209b3dbafc8d158f44fa4c3fbf7d6d1a3787fc045b2b3edcdc22c77e185\",\"100d976293f5f236e160fe2b5a7177bc806123f675845416b725b7f9e1cb7fa9653c168e986d361e628778f75f8090eb\"]],\"gamma_abc_g1\":[[\"05bafef7b33972046aba13ae281fc917bbda64b4d36b14b2275341c8a94bac022ba8e6372553c6318dffd407f6592be2\",\"14ba788a3b794c1d864dbf3562796c55892900d47720a3c8f489eaabf38015c0d3e80610b86d280fe5b1759015d47488\"],[\"03cf3812c7b2125eefc25e58b07ac7f60b74c7116ebdfd22557d73900cfce84217f8e9ad4a31d13d9e0c92fef7d8c810\",\"120dfcc09851d616a105e6a838f5952d00f962ad95fae6f2035ec17e71e02137d28a9d8210056647e3cc51493b4e91fd\"],[\"0819420574a08b2d695ebd7b876f2d85f09958faa1879c2c6b003ce70459579470c6903643d593a4dc613fa30d61d186\",\"157ad3bc9d8cb5ccc92be269bfc53b081ff7cb188ba2f8ac5cafea457029be69310e0209002357e4e73bf275ecad6798\"]],\"gamma_g2\":[[\"02f0d09818887c2a359678b971527509d52fa4f3acb38006c2fedac5cb10e0d3b07e62394e17712053b5e4607c27225c\",\"19a944313e543976666dbf9c04b3796171fb8989034b4c830e92e5f9bb5986472d578ecb59e1c9c71b7f28807c6c7569\"],[\"06e289502bd923ea87e6be5434290befc910d116afba0e72b9567bd4da9441e6ce6da71ed87b8901a9e430bea17edd2a\",\"057a96c8acc19890e5311f8c1c35bace326079615f6b8653da925af6df231c9d47c74674cda609b9e164a9e691513b1e\"]]}"))

  path := "/tmp/plonky2_proof/0"

	common_circuit_data, _ := os.ReadFile(path + "/common_circuit_data.json")

	proof_with_public_inputs, _ := os.ReadFile(path + "/proof_with_public_inputs.json")

	verifier_only_circuit_data, _ := os.ReadFile(path + "/verifier_only_circuit_data.json")

	worker.GenerateProof(string(common_circuit_data), string(proof_with_public_inputs), string(verifier_only_circuit_data), "/tmp/groth16-keystore/0/")
}
