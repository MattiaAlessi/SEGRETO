use pyo3::prelude::*;
use pyo3::exceptions::PyValueError;

use chacha20poly1305::{Key, XChaCha20Poly1305, XNonce, aead::{Aead, KeyInit}};
use x25519_dalek::{PublicKey as XPublicKey, StaticSecret as XStaticSecret};
use ed25519_dalek::{Signer, Verifier, SigningKey, VerifyingKey, Signature};
use argon2::Argon2;
use blake2::Blake2bVar;
use blake2::digest::{Update, VariableOutput};
use rand::rngs::OsRng;

#[pyfunction]
fn hello(name: &str, surname: &str) -> PyResult<String> {
    Ok(format!("Hello, {name} {surname}"))

}




#[pyfunction]
fn random_bytes(n: usize) -> PyResult<Vec<u8>> {
    use rand::RngCore;
    let mut buf = vec![0u8; n];
    OsRng.fill_bytes(&mut buf);
    Ok(buf)
}

#[pyfunction]
fn encrypt(key: &[u8], nonce: &[u8], plaintext: &[u8]) -> PyResult<Vec<u8>> {
    if key.len() != 32 {
        return Err(PyValueError::new_err("The keys must be 32 bytes"));
    }
    if nonce.len() != 24 {
        return Err(PyValueError::new_err("The nonce must be exactly 24 bytes"));
    }

    let cipher = XChaCha20Poly1305::new(Key::from_slice(key));
    let nonce = XNonce::from_slice(nonce);

    cipher
        .encrypt(nonce, plaintext)
        .map_err(|_| PyValueError::new_err("Encryption failed"))
}

#[pyfunction]
fn decrypt(key: &[u8], nonce: &[u8], ciphertext: &[u8]) -> PyResult<Vec<u8>> {
    if key.len() != 32 {
        return Err(PyValueError::new_err("The keys must be 32 bytes"));
    }
    if nonce.len() != 24 {
        return Err(PyValueError::new_err("The nonce must be exactly 24 bytes"));
    }



    let cipher = XChaCha20Poly1305::new(Key::from_slice(key));
    let nonce = XNonce::from_slice(nonce);

    cipher
        .decrypt(nonce, ciphertext)
        .map_err(|_| PyValueError::new_err("Decryption failed: tampered data or wrong key"))

}

/// Generate an X25519 keypair. Returns (secret, public), both 32 bytes.
#[pyfunction]
fn x25519_keypair() -> PyResult<(Vec<u8>, Vec<u8>)> {
    let secret = XStaticSecret::random_from_rng(OsRng);
    let public = XPublicKey::from(&secret);
    Ok((secret.to_bytes().to_vec(), public.as_bytes().to_vec()))
}

/// Derive the shared secret from your secret key and the peer's public key.
#[pyfunction]
fn x25519_shared_secret(secret: &[u8], peer_public: &[u8]) -> PyResult<Vec<u8>> {
    if secret.len() != 32 {
        return Err(PyValueError::new_err("The secret key must be 32 bytes"));
    }
    if peer_public.len() != 32 {
        return Err(PyValueError::new_err("The public key must be 32 bytes"));
    }

    let mut sk = [0u8; 32];
    sk.copy_from_slice(secret);
    let mut pk = [0u8; 32];
    pk.copy_from_slice(peer_public);
    let secret = XStaticSecret::from(sk);
    let public = XPublicKey::from(pk);
    Ok(secret.diffie_hellman(&public).as_bytes().to_vec())
}





#[pyfunction]
fn ed25519_keypair() -> PyResult<(Vec<u8>, Vec<u8>)> {
    let mut seed = [0u8; 32];

    use rand::RngCore;
    OsRng.fill_bytes(&mut seed);
    let signing = SigningKey::from_bytes(&seed);
    let verifying = signing.verifying_key();
    Ok((signing.to_bytes().to_vec(), verifying.as_bytes().to_vec()))
}

#[pyfunction]
fn ed25519_sign(secret: &[u8], message: &[u8]) -> PyResult<Vec<u8>> {
    if secret.len() != 32 {
        return Err(PyValueError::new_err("The secret key must be 32 bytes"));
    }

    let mut seed = [0u8; 32];
    seed.copy_from_slice(secret);
    let signing = SigningKey::from_bytes(&seed);
    Ok(signing.sign(message).to_bytes().to_vec())
}






#[pyfunction]
fn ed25519_verify(public: &[u8], message: &[u8], signature: &[u8]) -> PyResult<bool> {
    if public.len() != 32 {
        return Err(PyValueError::new_err("The public key must be 32 bytes"));
    }
    if signature.len() != 64 {
        return Err(PyValueError::new_err("The signature must be 64 bytes"));
    }

    let mut pk = [0u8; 32];
    pk.copy_from_slice(public);
    let mut sig = [0u8; 64];
    sig.copy_from_slice(signature);

    let verifying = match VerifyingKey::from_bytes(&pk) {
        Ok(vk) => vk,
        Err(_) => return Ok(false),
    };
    Ok(verifying.verify(message, &Signature::from_bytes(&sig)).is_ok())
}

#[pyfunction]
fn argon2id_key(password: &[u8], salt: &[u8]) -> PyResult<Vec<u8>> {
    if salt.len() < 8 {
        return Err(PyValueError::new_err("The salt must be at least 8 bytes"));
    }

    
    
    let params = argon2::Params::new(64 * 1024, 3, 1, Some(32))
        .map_err(|_| PyValueError::new_err("Invalid Argon2 parameters"))?;
    let argon2 = Argon2::new(argon2::Algorithm::Argon2id, argon2::Version::V0x13, params);

    let mut out = [0u8; 32];
    argon2
        .hash_password_into(password, salt, &mut out)
        .map_err(|_| PyValueError::new_err("Argon2id key derivation failed"))?;
    Ok(out.to_vec())
}



#[pyfunction]
fn blake2b(data: &[u8], digest_size: usize) -> PyResult<Vec<u8>> {
    if digest_size == 0 || digest_size > 64 {
        return Err(PyValueError::new_err("digest_size must be between 1 and 64"));
    }
    let mut hasher = Blake2bVar::new(digest_size)
        .map_err(|_| PyValueError::new_err("Invalid BLAKE2b digest size"))?;
    hasher.update(data);
    let out = hasher.finalize_boxed();
    Ok(out.to_vec())
}

#[pymodule]
fn crypto_core(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_function(wrap_pyfunction!(hello, m)?)?;
    m.add_function(wrap_pyfunction!(random_bytes, m)?)?;
    m.add_function(wrap_pyfunction!(encrypt, m)?)?;
    m.add_function(wrap_pyfunction!(decrypt, m)?)?;
    m.add_function(wrap_pyfunction!(x25519_keypair, m)?)?;
    m.add_function(wrap_pyfunction!(x25519_shared_secret, m)?)?;
    m.add_function(wrap_pyfunction!(ed25519_keypair, m)?)?;
    m.add_function(wrap_pyfunction!(ed25519_sign, m)?)?;
    m.add_function(wrap_pyfunction!(ed25519_verify, m)?)?;
    m.add_function(wrap_pyfunction!(argon2id_key, m)?)?;
    m.add_function(wrap_pyfunction!(blake2b, m)?)?;
    Ok(())
}
