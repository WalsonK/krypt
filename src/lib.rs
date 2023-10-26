extern crate bcrypt;

use bcrypt::{hash, verify};


fn alternate_concatenate(password: String, pepper: String) -> String {
    let mut result = String::new();
    let mut i = 0;
    let mut j = 0;

    let special = if password.len() % 4 <= 1 { 2 } else { password.len() % 4 };

    while i < password.len() && j < pepper.len() {
        let end_i = i + special.min(password.len() - i);
        let end_j = j + special.min(pepper.len() - j);
        result.push_str(&password[i..end_i]);
        result.push_str(&pepper[j..end_j]);
        i = end_i;
        j = end_j;
    }

    result.push_str(&password[i..]);
    result.push_str(&pepper[j..]);

    result
}

#[no_mangle]
pub extern "C" fn hash_pass(pass: *mut std::os::raw::c_char, secret: *mut std::os::raw::c_char) -> *mut std::os::raw::c_char {
    // Convert C input to String
    let c_pass = unsafe { std::ffi::CStr::from_ptr(pass) };
    let c_secret = unsafe { std::ffi::CStr::from_ptr(secret) };
    let pass_str = c_pass.to_str().expect("Invalid pass string").to_string();
    let secret_str = c_secret.to_str().expect("Invalid secret string").to_string();


    let concatenate_password = alternate_concatenate(pass_str, secret_str);

    let hashed_password = hash(concatenate_password, 10)
        .expect("Erreur lors du hachage du mot de passe");

    std::ffi::CString::new(hashed_password).unwrap().into_raw()
}

#[no_mangle]
pub extern "C" fn compare_pass(tapped_password: *mut std::os::raw::c_char, secret: *mut std::os::raw::c_char, bdd_password: *mut std::os::raw::c_char) -> bool {
    // Get String from C
    let c_tapped = unsafe { std::ffi::CStr::from_ptr(tapped_password) };
    let c_secret = unsafe { std::ffi::CStr::from_ptr(secret) };
    let c_bdd = unsafe { std::ffi::CStr::from_ptr(bdd_password) };

    let tapped_str = c_tapped.to_str().expect("Invalid pass string").to_string();
    let secret_str = c_secret.to_str().expect("Invalid secret string").to_string();
    let concatenate_password = alternate_concatenate(tapped_str, secret_str);

    // Unwrap or set to ""
    let bdd_str = c_bdd.to_str().unwrap_or_else(|e| {
        eprintln!("Erreur lors de la conversion du mot de passe bdd : {:?}", e);
        return "";
    });

    match verify(&concatenate_password, bdd_str) {
        Ok(true) => { true }
        Ok(false) => { false }
        Err(_) => { false }
    }
}
