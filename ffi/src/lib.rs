use std::ffi::{CStr, CString};

mod bindings {
    #![allow(
        unused,
        non_upper_case_globals,
        non_camel_case_types,
        non_snake_case,
        // Silence "128-bit integers don't currently have a known stable ABI" warnings
        improper_ctypes,
        // Silence "constants have by default a `'static` lifetime" clippy warnings
        clippy::redundant_static_lifetimes,
        // https://github.com/rust-lang/rust-bindgen/issues/1651
        deref_nullptr,
    )]
    include!(concat!(env!("OUT_DIR"), "/bindings.rs"));
}

pub fn generate_groth16_proof(
    common_circuit_data: &str,
    proof_with_public_inputs: &str,
    verifier_only_circuit_data: &str,
) -> String {
    let c_common_circuit_data = CString::new(common_circuit_data).unwrap();
    let c_proof_with_public_inputs = CString::new(proof_with_public_inputs).unwrap();
    let c_verifier_only_circuit_data = CString::new(verifier_only_circuit_data).unwrap();
    unsafe {
        let c_proof = bindings::GenerateGroth16Proof(
            c_common_circuit_data.into_raw(),
            c_proof_with_public_inputs.into_raw(),
            c_verifier_only_circuit_data.into_raw(),
        );
        let proof = CStr::from_ptr(c_proof).to_string_lossy().into_owned();
        libc::free(c_proof as *mut libc::c_void);
        proof
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generate_groth16_proof_test() {
        generate_groth16_proof(
            &std::fs::read_to_string("../testdata/common_circuit_data.json").unwrap(),
            &std::fs::read_to_string("../testdata/proof_with_public_inputs.json").unwrap(),
            &std::fs::read_to_string("../testdata/verifier_only_circuit_data.json").unwrap(),
        );
    }
}
