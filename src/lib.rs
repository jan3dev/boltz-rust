/// Error Module
pub mod error;
/// Blockchain Network module. Currently only contains electrum interface.
pub mod network;
/// payjoin
pub mod payjoin;

pub use payjoin::payjoin::{create_taxi_transaction_internal, final_tx, UtxoFFI};
pub use payjoin::op_return::create_liquid_tx_with_op_return_internal;

pub use bitcoin::{
    blockdata::locktime::absolute::LockTime,
    hashes::{hash160, ripemd160, sha256, Hash},
    secp256k1::rand::thread_rng,
    secp256k1::schnorr::Signature,
    secp256k1::{Keypair, Message, Secp256k1, XOnlyPublicKey},
    Address, Amount, PublicKey,
};

pub use elements::{
    address::Address as ElementsAddress,
    address::Address as EAddress,

    encode::{Encodable, serialize},
    AssetId,
    hex::{FromHex, ToHex},
    locktime::LockTime as ElementsLockTime,
    opcodes::all::*,
    pset::{PartiallySignedTransaction, Output},
    pset::serialize::Serialize,
    script::{Builder as EBuilder, Script},
    secp256k1_zkp::{Keypair as ZKKeyPair, Secp256k1 as ZKSecp256k1},
    AddressParams,
    confidential::{Asset, Value, Nonce},
    Transaction, TxIn, TxOut, TxInWitness, TxOutWitness, OutPoint, AssetIssuance,
    Sequence,
};

pub use lightning_invoice::Bolt11Invoice;
use std::cell::RefCell;
use std::ffi::{c_char, CStr, CString};
use std::panic::{self, AssertUnwindSafe, catch_unwind};
use std::ptr;
use std::str::FromStr;

use base64::Engine;

use hex::{decode, encode};
use network::electrum::ElectrumConfig;

#[no_mangle]
pub extern "C" fn get_key_pair() -> *mut c_char {
    let secp = Secp256k1::new();
    let (secret_key, public_key) = secp.generate_keypair(&mut thread_rng());

    let secret_key_hex = hex::encode(secret_key.as_ref());
    let public_key_hex = hex::encode(public_key.serialize());

    let combined_string = format!("{};{}", secret_key_hex, public_key_hex);

    match CString::new(combined_string) {
        Ok(c_str_combined) => c_str_combined.into_raw(),
        Err(_) => ptr::null_mut(),
    }
}

#[no_mangle]
pub extern "C" fn sign_message_schnorr(
    message: *const c_char,
    private_key: *const c_char,
) -> *mut c_char {
    let message_str = unsafe { CStr::from_ptr(message).to_str().unwrap().trim() };
    let private_key_str = unsafe { CStr::from_ptr(private_key).to_str().unwrap().trim() };

    let message_hash = sha256::Hash::hash(message_str.as_bytes());
    let msg = match Message::from_digest_slice(message_hash.as_ref()) {
        Ok(m) => m,
        Err(e) => {
            log_message(&format!("[Rust] Sign schnorr - Error: {:?}", e));
            return ptr::null_mut();
        }
    };

    let keypair = match Keypair::from_str(private_key_str) {
        Ok(k) => k,
        Err(e) => {
            log_message(&format!("[Rust] Sign schnorr - Error: {:?}", e));
            return ptr::null_mut();
        }
    };

    let sig = keypair.sign_schnorr(msg);
    let sig_hex = hex::encode(sig.serialize());
    let c_sig = CString::new(sig_hex).unwrap();
    c_sig.into_raw()
}

#[no_mangle]
pub extern "C" fn verify_signature_schnorr(
    signature: *const c_char,
    message: *const c_char,
    public_key: *const c_char,
) -> i32 {
    let message_str = unsafe { CStr::from_ptr(message).to_str().unwrap().trim() };
    let signature_str = unsafe { CStr::from_ptr(signature).to_str().unwrap().trim() };
    let public_key_str = unsafe { CStr::from_ptr(public_key).to_str().unwrap().trim() };

    let message_hash = sha256::Hash::hash(message_str.as_bytes());
    let msg = match Message::from_digest_slice(message_hash.as_ref()) {
        Ok(m) => m,
        Err(_) => return 0,
    };

    let sig_bytes = match hex::decode(signature_str) {
        Ok(s) => s,
        Err(_) => return 0,
    };

    let sig = match Signature::from_slice(&sig_bytes) {
        Ok(s) => s,
        Err(_) => return 0,
    };

    let publicKey = match PublicKey::from_str(public_key_str) {
        Ok(p) => p,
        Err(_) => return 0,
    };

    let x_only_pub_key = XOnlyPublicKey::from(publicKey);

    let secp = Secp256k1::new();
    match secp.verify_schnorr(&sig, &msg, &x_only_pub_key) {
        Ok(_) => 1,
        Err(_) => 0,
    }
}

#[no_mangle]
pub extern "C" fn create_liquid_tx_with_op_return(
    mnemonic: *const c_char,
    send_amount: u64,
    fee_rate: f64,
    send_address: *const c_char,
    change_address: *const c_char,
    utxos: *const UtxoFFI,
    utxos_len: usize,
    op_return_data: *const c_char,
    is_testnet: bool,
) -> TxResult {
    match create_liquid_tx_with_op_return_internal(
        mnemonic,
        send_amount,
        fee_rate,
        send_address,
        change_address,
        utxos,
        utxos_len,
        op_return_data,
        is_testnet,
    ) {
        Ok(pset_base64) => {
            let tx_c_string = CString::new(pset_base64)
                .unwrap_or_else(|_| CString::new("String conversion failed").unwrap());
            TxResult {
                tx_ptr: tx_c_string.into_raw(),
                error_msg: std::ptr::null_mut(),
            }
        }
        Err(e) => {
            let error_msg = CString::new(format!("Error: {:?}", e))
                .unwrap_or_else(|_| CString::new("Unknown error").unwrap())
                .into_raw();
            TxResult {
                tx_ptr: std::ptr::null_mut(),
                error_msg,
            }
        }
    }
}

#[repr(C)]
pub struct TxResult {
    pub tx_ptr: *mut c_char,
    pub error_msg: *mut c_char,
}

#[no_mangle]
pub extern "C" fn create_taxi_transaction(
    send_amount: u64,
    send_address: *const c_char,
    change_address: *const c_char,
    utxos: *const UtxoFFI,
    utxos_len: usize,
    user_agent: *const c_char,
    api_key: *const c_char,
    subtract_fee_from_amount: bool, 
    is_lowball: bool,
    is_testnet: bool,
) -> TxResult {
    match create_taxi_transaction_internal(
        send_amount,
        send_address,
        change_address,
        utxos,
        utxos_len,
        user_agent,
        api_key,
        subtract_fee_from_amount,
        is_lowball,
        is_testnet,
    ) {
        Ok(tx_string) => {   
            let tx_c_string = CString::new(tx_string)
                .unwrap_or_else(|e| {
                    log::error!("Failed to convert string: {:?}", e);
                    CString::new("String conversion failed").unwrap()
                });
            let tx_ptr = tx_c_string.into_raw(); // Convert CString to *mut c_char
            TxResult {
                tx_ptr,
                error_msg: std::ptr::null_mut(),
            }
        }
        Err(e) => {
            let error_msg = CString::new(format!("{}", e))
                .unwrap_or_else(|_| CString::new("Unknown error").unwrap())
                .into_raw();
            TxResult {
                tx_ptr: std::ptr::null_mut(),
                error_msg,
            }
        }
    }
}

#[no_mangle]
pub extern "C" fn create_final_taxi_pset(
    client_signed_pset: *const c_char,
    server_signed_pset: *const c_char,
) -> TxResult {
    let result = (|| -> Result<TxResult, Box<dyn std::error::Error>> {
        let client_signed_pset_str = unsafe { 
            CStr::from_ptr(client_signed_pset)
                .to_str()?
                .trim()
                .to_string()
        };

        let server_signed_pset_str = unsafe { 
            CStr::from_ptr(server_signed_pset)
                .to_str()?
                .trim()
                .to_string()
        };

        let decoded_client = base64::engine::general_purpose::STANDARD.decode(&client_signed_pset_str)?;
        let decoded_server = base64::engine::general_purpose::STANDARD.decode(&server_signed_pset_str)?;

        let pset_client = elements::encode::deserialize::<elements::pset::PartiallySignedTransaction>(&decoded_client)?;
        let pset_server = elements::encode::deserialize::<elements::pset::PartiallySignedTransaction>(&decoded_server)?;

        let tx = final_tx(pset_client, pset_server)?;

        let tx_hex = elements::encode::serialize_hex(&tx);
        let c_str_tx = CString::new(tx_hex)?;
        Ok(TxResult {
            tx_ptr: c_str_tx.into_raw(),
            error_msg: std::ptr::null_mut(),
        })
    })();

    match result {
        Ok(tx_result) => tx_result,
        Err(e) => {
            let error_message = CString::new(e.to_string()).unwrap();
            TxResult {
                tx_ptr: std::ptr::null_mut(),
                error_msg: error_message.into_raw(),
            }
        }
    }
}

#[no_mangle]
pub extern "C" fn rust_cstr_free(s: *mut c_char) {
    unsafe {
        if s.is_null() {
            return;
        }
        drop(CString::from_raw(s));
    };
}

// Logging
type LogCallback = extern "C" fn(*const c_char);

static mut LOG_CALLBACK: Option<LogCallback> = None;

#[no_mangle]
pub extern "C" fn register_log_callback(callback: LogCallback) {
    unsafe {
        LOG_CALLBACK = Some(callback);
    }
}

pub fn log_message(message: &str) {
    let c_str = CString::new(message).unwrap();
    unsafe {
        if let Some(callback) = LOG_CALLBACK {
            callback(c_str.as_ptr());
        }
    }
}

// Error Reporting
thread_local! {
    static LAST_ERROR: RefCell<Option<CString>> = RefCell::new(None);
}

/// Sets the last error message
fn set_last_error(message: &str) {
    LAST_ERROR.with(|last| {
        *last.borrow_mut() = Some(CString::new(message).expect("Error message contains null byte"));
    });
}

/// Retrieves the last error message, if any.
#[no_mangle]
pub extern "C" fn get_last_error() -> *const c_char {
    LAST_ERROR.with(|last| {
        last.borrow()
            .as_ref()
            .map_or(std::ptr::null(), |message| message.as_ptr())
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use bitcoin::secp256k1;
    use secp256k1::rand::thread_rng;
    use secp256k1::Secp256k1;
    use std::ffi::CString;

    // Helper function to convert Rust string to C string pointer
    fn to_c_str(s: &str) -> *const c_char {
        CString::new(s).unwrap().into_raw() as *const c_char
    }

    // Helper function to convert C string pointer back to Rust String
    fn from_c_str(c_str: *mut c_char) -> String {
        unsafe { CString::from_raw(c_str).to_string_lossy().into_owned() }
    }

    #[test]
    fn test_sign_and_verify_schnorr() {
        let secp = Secp256k1::new();
        let (secret_key, public_key) = secp.generate_keypair(&mut thread_rng());

        let message = "test message";
        let private_key_hex = hex::encode(secret_key.secret_bytes());
        let public_key_hex = hex::encode(public_key.serialize());

        // Convert test data to C strings
        let message_c_str = to_c_str(message);
        let private_key_c_str = to_c_str(&private_key_hex);
        let public_key_c_str = to_c_str(&public_key_hex);

        let signature_c_str = sign_message_schnorr(message_c_str, private_key_c_str);
        assert!(!signature_c_str.is_null(), "Signature should not be null");

        let signature_str = from_c_str(signature_c_str);

        let verify_result =
            verify_signature_schnorr(to_c_str(&signature_str), message_c_str, public_key_c_str);

        assert_eq!(verify_result, 1, "Signature verification failed");

        unsafe {
            let _ = CString::from_raw(message_c_str as *mut c_char);
            let _ = CString::from_raw(private_key_c_str as *mut c_char);
            let _ = CString::from_raw(public_key_c_str as *mut c_char);
        }
    }
}