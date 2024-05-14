use libc::c_char;
use std::ffi::{CStr, CString};

#[link(name = "g16verifier")]
extern "C" {
    fn GenerateGroth16Proof(path: *const c_char) -> *mut c_char;
}

pub fn generate_groth16_proof(path: &str) -> String {
    let c_path = CString::new(path).unwrap();
     unsafe {
        let c_proof = GenerateGroth16Proof(c_path.as_ptr());
        let proof = CStr::from_ptr(c_proof).to_string_lossy().into_owned();
        libc::free(c_proof as *mut libc::c_void);
        proof
    }
}
