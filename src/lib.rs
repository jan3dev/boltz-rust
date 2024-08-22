/// Error Module
pub mod error;
/// Blockchain Network module. Currently only contains electrum interface.
pub mod network;
/// payjoin
pub mod payjoin;
/// core swap logic
pub mod swaps;
/// utilities (key, preimage, error)
pub mod util;

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

use crate::util::secrets::Preimage;

use hex::{decode, encode};
use network::electrum::ElectrumConfig;

pub use swaps::{
    bitcoin::{BtcSwapScript, BtcSwapTx},
    bitcoinv2::{BtcSwapScriptV2, BtcSwapTxV2},
    boltz::{SwapTxKind, SwapType},
    liquid::LBtcSwapScript,
    liquid::LBtcSwapTx,
    liquidv2::{LBtcSwapScriptV2, LBtcSwapTxV2},
};

#[no_mangle]
pub extern "C" fn validate_submarine(
    preimage_hash: *const c_char,
    claim_public_key: *const c_char,
    refund_public_key: *const c_char,
    timeout_block_height: u32,
    lockup_address: *const c_char,
    redeem_script: *const c_char,
    blinding_key: *const c_char,
) -> i32 {
    let claim_public_key_str = unsafe { CStr::from_ptr(claim_public_key).to_str().unwrap().trim() };
    let refund_public_key_str =
        unsafe { CStr::from_ptr(refund_public_key).to_str().unwrap().trim() };

    let claim_public_key = PublicKey::from_str(claim_public_key_str).unwrap();
    let refund_public_key = PublicKey::from_str(refund_public_key_str).unwrap();

    let preimage_hash_str = unsafe { CStr::from_ptr(preimage_hash).to_str().unwrap().trim() };
    let preimage_hash_ripemd =
        ripemd160::Hash::hash(decode(&preimage_hash_str).unwrap().as_slice()).to_byte_array();
    let blinding_key_str = unsafe { CStr::from_ptr(blinding_key).to_str().unwrap().trim() };
    let blinding_key: ZKKeyPair =
        ZKKeyPair::from_seckey_str(&ZKSecp256k1::new(), &blinding_key_str)
            .unwrap()
            .into();

    let locktime = LockTime::from_height(timeout_block_height).unwrap();

    let response_lockup_address =
        unsafe { CStr::from_ptr(lockup_address).to_str().unwrap().trim() };
    let response_redeem_script = unsafe { CStr::from_ptr(redeem_script).to_str().unwrap().trim() };

    let reconstructed_script = EBuilder::new()
        .push_opcode(OP_HASH160)
        .push_slice(&preimage_hash_ripemd)
        .push_opcode(OP_EQUAL)
        .push_opcode(elements::opcodes::all::OP_IF)
        .push_key(&claim_public_key)
        .push_opcode(OP_ELSE)
        .push_int(locktime.to_consensus_u32() as i64)
        .push_opcode(OP_CLTV)
        .push_opcode(OP_DROP)
        .push_key(&refund_public_key)
        .push_opcode(OP_ENDIF)
        .push_opcode(OP_CHECKSIG)
        .into_script();

    let reconstructed_address = EAddress::p2wsh(
        &reconstructed_script,
        Some(blinding_key.public_key()),
        &AddressParams::LIQUID,
    );

    let reconstructed_address_str = reconstructed_address.to_string();
    let reconstructed_script_str = reconstructed_script.as_bytes().to_hex();

    let script_matches = response_redeem_script == reconstructed_script_str;
    let address_matches = response_lockup_address == reconstructed_address_str;

    log_message(&format!(
        "[Rust] validate submarine - response_redeem_script: {:?}, reconstructed_script_str: {:?}, script_matches: {:?}, response_lockup_address: {:?}, reconstructed_address: {:?}, address_matches: {:?},",
        response_redeem_script,
        reconstructed_script_str,
        script_matches,
        response_lockup_address,
        reconstructed_address,
        address_matches
    ));

    (script_matches && address_matches) as i32
}

#[no_mangle]
pub extern "C" fn extract_claim_public_key(comparison_script: *const c_char) -> *mut c_char {
    let c_str = unsafe { CStr::from_ptr(comparison_script).to_str().unwrap().trim() };
    let script = elements::script::Script::from_hex(c_str);

    let binding = script.unwrap();
    let mut iter = binding.instructions();
    let mut found_op_if = false;
    while let Some(instruction) = iter.next() {
        let ins = instruction.unwrap();
        if ins.op() != None {
            if ins.op().unwrap() == elements::opcodes::all::OP_IF {
                found_op_if = true;
                continue;
            }
        }
        if found_op_if {
            found_op_if = false;
            let claim_public_key = PublicKey::from_slice(ins.push_bytes().unwrap())
                .unwrap()
                .to_bytes();
            let claim_public_key_hex = hex::encode(&claim_public_key);
            return CString::new(claim_public_key_hex.to_owned())
                .unwrap()
                .into_raw();
        }
    }
    return CString::new("").unwrap().into_raw();
}

pub enum TransactionType {
    Claim,
    Refund,
}

#[no_mangle]
pub extern "C" fn create_and_sign_claim_transaction(
    redeem_script: *const c_char,
    blinding_key: *const c_char,
    onchain_address: *const c_char,
    private_key: *const c_char,
    preimage: *const c_char,
    tx: *const c_char,
    fees: u64,
) -> *mut c_char {
    match panic::catch_unwind(AssertUnwindSafe(|| {
        create_and_sign_transaction(
            TransactionType::Claim,
            redeem_script,
            blinding_key,
            onchain_address,
            private_key,
            Some(preimage),
            tx,
            fees,
        )
    })) {
        Ok(result) => result,
        Err(_) => CString::new("Panic occurred during create_and_sign_claim_transaction")
            .unwrap()
            .into_raw(),
    }
}

#[no_mangle]
pub extern "C" fn create_and_sign_refund_transaction(
    redeem_script: *const c_char,
    blinding_key: *const c_char,
    onchain_address: *const c_char,
    private_key: *const c_char,
    tx: *const c_char,
    fees: u64,
) -> *mut c_char {
    match panic::catch_unwind(AssertUnwindSafe(|| {
        create_and_sign_transaction(
            TransactionType::Refund,
            redeem_script,
            blinding_key,
            onchain_address,
            private_key,
            None, // No preimage for refund
            tx,
            fees,
        )
    })) {
        Ok(result) => result,
        Err(_) => CString::new("Panic occurred during create_and_sign_refund_transaction")
            .unwrap()
            .into_raw(),
    }
}

#[no_mangle]
pub extern "C" fn create_and_sign_transaction(
    transaction_type: TransactionType,
    redeem_script: *const c_char,
    blinding_key: *const c_char,
    onchain_address: *const c_char,
    private_key: *const c_char,
    preimage: Option<*const c_char>,
    tx: *const c_char,
    fees: u64,
) -> *mut c_char {
    let redeem_script_str = unsafe { CStr::from_ptr(redeem_script).to_str().unwrap().trim() };
    let blinding_key_str = unsafe { CStr::from_ptr(blinding_key).to_str().unwrap().trim() };
    let onchain_address_str = unsafe { CStr::from_ptr(onchain_address).to_str().unwrap().trim() };
    let private_key_str = unsafe { CStr::from_ptr(private_key).to_str().unwrap().trim() };
    // Preimage is only used for claim transactions
    let preimage_str = preimage.map(|p| unsafe { CStr::from_ptr(p).to_str().unwrap().trim() });
    let tx_str = unsafe { CStr::from_ptr(tx).to_str().unwrap().trim() };

    log_message(&format!(
        "[Rust] create tx - params - redeem_script: {:?}, blinding_key: {:?}, onchain_address: {:?}, private_key: {:?}, preimage: {:?}",
        redeem_script_str,
        blinding_key_str,
        onchain_address_str,
        private_key_str,
        preimage_str
    ));

    // Create the swap script
    let swap_script: LBtcSwapScript = match transaction_type {
        TransactionType::Claim => {
            match LBtcSwapScript::reverse_from_str(redeem_script_str, blinding_key_str) {
                Ok(script) => script,
                Err(e) => {
                    let error_message = CString::new(format!("Error: {:?}", e)).unwrap();
                    log_message(&format!(
                        "[Rust] Claim - Error creating LBtcSwapScript: {:?}",
                        error_message
                    ));
                    return error_message.into_raw();
                }
            }
        }
        TransactionType::Refund => {
            match LBtcSwapScript::submarine_from_str(redeem_script_str, blinding_key_str) {
                Ok(script) => script,
                Err(e) => {
                    let error_message = CString::new(format!("Error: {:?}", e)).unwrap();
                    log_message(&format!(
                        "[Rust] Refund - Error creating LBtcSwapScript: {:?}",
                        error_message
                    ));
                    return error_message.into_raw();
                }
            }
        }
    };

    let network_config = &ElectrumConfig::default_liquid();
    log_message(&format!(
        "[Rust] create tx - swap_script - sender_pubkey: {:?}, hashlock: {:?}, timelock: {:?}",
        swap_script.sender_pubkey.to_string(),
        swap_script.hashlock.to_string(),
        swap_script.locktime
    ));

    // Create the swap transaction based on the transaction type
    let liquid_swap_tx_result = match transaction_type {
        TransactionType::Claim => LBtcSwapTx::new_claim(
            swap_script.clone(),
            onchain_address_str.to_string(),
            tx_str.to_string(),
            network_config,
        ),
        TransactionType::Refund => LBtcSwapTx::new_refund(
            swap_script.clone(),
            onchain_address_str.to_string(),
            tx_str.to_string(),
            network_config,
        ),
    };

    let liquid_swap_tx: LBtcSwapTx = match liquid_swap_tx_result {
        Ok(tx) => tx,
        Err(e) => {
            let error_message = CString::new(format!("Error: {:?}", e)).unwrap();
            log_message(&format!(
                "[Rust] Error creating LBtcSwapTx: {:?}",
                error_message
            ));
            return error_message.into_raw();
        }
    };

    log_message(&format!(
        "[Rust] Create tx - liquid_swap_tx: {:#?}",
        liquid_swap_tx
    ));

    // Sign tx (claim or refund)
    let keypair = Keypair::from_str(private_key_str).unwrap();
    let final_tx = match transaction_type {
        TransactionType::Claim => {
            let preimage =
                Preimage::from_str(preimage_str.expect("Preimage required for claim")).unwrap();
            liquid_swap_tx
                .sign_claim(&keypair, &preimage, fees)
                .unwrap()
        }
        TransactionType::Refund => liquid_swap_tx.sign_refund(&keypair, fees).unwrap(),
    };

    let mut serialized_tx = Vec::new();
    final_tx
        .consensus_encode(&mut serialized_tx)
        .expect("Transaction serialization failed");

    let final_tx_hex = hex::encode(serialized_tx);
    log_message(&format!(
        "[Rust] Create tx - Finalized tx: {}",
        final_tx_hex
    ));

    let c_str_tx: CString = CString::new(final_tx_hex).expect("CString::new failed");
    c_str_tx.into_raw()
}

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

    #[test]
    fn test_create_liquid_tx_with_op_return() {
        use elements::OutPoint;
        use elements::confidential::{Asset, Value};
        use std::ffi::CString;

        fn create_utxo(txid: &str, vout: u32, value: u64, asset_id: &str) -> UtxoFFI {
            let blinding_key = elements::secp256k1_zkp::SecretKey::new(&mut rand::thread_rng());
            
            let elements_asset = Asset::Explicit(elements::AssetId::from_str(asset_id).unwrap());
            let elements_value = Value::Explicit(value);
            
            let asset_commitment = elements_asset.commitment();
            let value_commitment = elements_value.commitment();
        
            UtxoFFI {
                txid: CString::new(txid).unwrap().into_raw(),
                vout,
                value,
                script_pub_key: CString::new("76a914000000000000000000000000000000000000000088ac").unwrap().into_raw(),
                asset_id: CString::new(asset_id).unwrap().into_raw(),
                asset_bf: CString::new(hex::encode(blinding_key.secret_bytes())).unwrap().into_raw(),
                value_bf: CString::new(hex::encode(blinding_key.secret_bytes())).unwrap().into_raw(),
                asset_commitment: CString::new(hex::encode(asset_commitment.map(|c| c.to_hex()).unwrap_or_default())).unwrap().into_raw(),
                value_commitment: CString::new(hex::encode(value_commitment.map(|c| c.to_hex()).unwrap_or_default())).unwrap().into_raw(),
            }
        }
    
        let send_amount = 1_000_000;
        let fee_rate = 1.0;
        let send_address = to_c_str("VJL7JBzuzsfxSR8XbBJ9sDLKHyJLr5ccypeskmB4cgzNgyCvP2xYwfJXPqk9xPnQ1oA9RErgrYumsYF6");
        let change_address = to_c_str("VJL7JBzuzsfxSR8XbBJ9sDLKHyJLr5ccypeskmB4cgzNgyCvP2xYwfJXPqk9xPnQ1oA9RErgrYumsYF6");
        let liquid_asset_id = "6f0279e9ed041c3d710a9f57d0c02928416460c4b722ae3457a11eec381c526d";
        let utxos = vec![
            create_utxo("1234567890123456789012345678901234567890123456789012345678901234", 0, 2_000_000, liquid_asset_id),
            create_utxo("abcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcd", 1, 1_000_000, liquid_asset_id),
        ];
        let op_return_data = to_c_str("48656c6c6f20576f726c64"); // "Hello World" in hex
        let is_testnet = false;
    
        let result = create_liquid_tx_with_op_return(
            send_amount,
            fee_rate,
            send_address,
            change_address,
            utxos.as_ptr(),
            utxos.len(),
            op_return_data,
            is_testnet,
        );

        for utxo in utxos {
            unsafe {
                let _ = CString::from_raw(utxo.txid as *mut c_char);
                let _ = CString::from_raw(utxo.script_pub_key as *mut c_char);
                let _ = CString::from_raw(utxo.asset_id as *mut c_char);
                let _ = CString::from_raw(utxo.asset_bf as *mut c_char);
                let _ = CString::from_raw(utxo.value_bf as *mut c_char);
                let _ = CString::from_raw(utxo.asset_commitment as *mut c_char);
                let _ = CString::from_raw(utxo.value_commitment as *mut c_char);
            }
        }    

        assert!(result.error_msg.is_null(), "Error occurred: {:?}", unsafe { CStr::from_ptr(result.error_msg) });
        assert!(!result.tx_ptr.is_null(), "Transaction pointer is null");

        let tx_hex = unsafe { CStr::from_ptr(result.tx_ptr).to_string_lossy().into_owned() };
        let tx_bytes = hex::decode(&tx_hex).expect("Failed to decode hex");
        let tx: elements::Transaction = elements::encode::deserialize(&tx_bytes).expect("Failed to deserialize transaction");
    
        // verify the transaction structure
        assert_eq!(tx.version, 2, "Incorrect transaction version");
        assert_eq!(tx.input.len(), 2, "Incorrect number of inputs");
        assert!(tx.output.len() >= 3, "Incorrect number of outputs"); // At least 3: main output, OP_RETURN, and fee
    
        // verify inputs
        assert_eq!(tx.input[0].previous_output, OutPoint::new(elements::Txid::from_str("1234567890123456789012345678901234567890123456789012345678901234").unwrap(), 0));
        assert_eq!(tx.input[1].previous_output, OutPoint::new(elements::Txid::from_str("abcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcd").unwrap(), 1));
    
        // verify main output
        let main_output = &tx.output[0];
        assert_eq!(main_output.value, Value::Explicit(send_amount));
        assert_eq!(main_output.asset, Asset::Explicit(elements::AssetId::from_str(liquid_asset_id).unwrap()));
        assert_eq!(main_output.script_pubkey, ElementsAddress::from_str("VJL7JBzuzsfxSR8XbBJ9sDLKHyJLr5ccypeskmB4cgzNgyCvP2xYwfJXPqk9xPnQ1oA9RErgrYumsYF6").unwrap().script_pubkey());
    
        // verify OP_RETURN output
        let op_return_output = &tx.output[1];
        assert_eq!(op_return_output.value, Value::Explicit(0));
        assert_eq!(op_return_output.asset, Asset::Explicit(elements::AssetId::from_str(liquid_asset_id).unwrap()));
        assert!(op_return_output.script_pubkey.is_op_return());
        assert_eq!(op_return_output.script_pubkey.as_bytes()[2..], hex::decode("48656c6c6f20576f726c64").unwrap());
    
        // verify fee output
        let fee_output = tx.output.iter().find(|o| o.is_fee()).expect("Fee output not found");
        assert!(fee_output.value.explicit().unwrap() > 0, "Fee should be greater than 0");
        assert_eq!(fee_output.asset, Asset::Explicit(elements::AssetId::from_str(liquid_asset_id).unwrap()));
    
        // verify change output if present
        if tx.output.len() > 3 {
            let change_output = &tx.output[3];
            assert_eq!(change_output.asset, Asset::Explicit(elements::AssetId::from_str(liquid_asset_id).unwrap()));
            assert_eq!(change_output.script_pubkey, ElementsAddress::from_str("VJL7JBzuzsfxSR8XbBJ9sDLKHyJLr5ccypeskmB4cgzNgyCvP2xYwfJXPqk9xPnQ1oA9RErgrYumsYF6").unwrap().script_pubkey());
        }

        // verify fee output is the last output
        assert!(tx.output.last().unwrap().is_fee(), "Fee output should be the last output");
    
        unsafe {
            let _ = CString::from_raw(send_address as *mut c_char);
            let _ = CString::from_raw(change_address as *mut c_char);
            if !op_return_data.is_null() {
                let _ = CString::from_raw(op_return_data as *mut c_char);
            }
            if !result.tx_ptr.is_null() {
                let _ = CString::from_raw(result.tx_ptr);
            }
            if !result.error_msg.is_null() {
                let _ = CString::from_raw(result.error_msg);
            }
        }
    }
}