use std::ffi::CStr;
use std::os::raw::c_char;
extern crate elements;
extern crate rand;

use base64::Engine;
use rand::thread_rng;
use std::str::FromStr;
use std::collections::HashMap;

use elements::{secp256k1_zkp, Address, AssetId};
use elements::pset::{PartiallySignedTransaction, Output};
use elements::encode::serialize;
use elements::{Script, TxOut, TxOutWitness};
use elements::confidential::{Asset, Nonce, Value, AssetBlindingFactor, ValueBlindingFactor};
use elements::secp256k1_zkp::Secp256k1;
use elements::TxOutSecrets;

use bitcoin::PublicKey;

use super::server_api;
use super::pset;
use super::payjoin::convert_to_native_utxo;

pub fn create_liquid_tx_with_op_return_internal(
    send_amount: u64,
    fee_rate: f64,
    send_address: *const c_char,
    change_address: *const c_char,
    utxos: *const crate::UtxoFFI,
    utxos_len: usize,
    op_return_data: *const c_char,
    is_testnet: bool,
) -> Result<String, anyhow::Error> {
    let send_address_str = unsafe { CStr::from_ptr(send_address).to_str()? };
    let change_address_str = unsafe { CStr::from_ptr(change_address).to_str()? };
    let op_return_data_str = unsafe { CStr::from_ptr(op_return_data).to_str()? };
    let utxos_slice = unsafe { std::slice::from_raw_parts(utxos, utxos_len) };

    let lbtc_asset_id = if is_testnet {
        AssetId::from_str("144c654344aa716d6f3abcc1ca90e5641e4e2a7f633bc09fe3baf64585819a49")?
    } else {
        AssetId::from_str("6f0279e9ed041c3d710a9f57d0c02928416460c4b722ae3457a11eec381c526d")?
    };

    let op_return_data = hex::decode(op_return_data_str)?;
    let send_address = Address::from_str(send_address_str)?;
    let change_address = Address::from_str(change_address_str)?;
    let client_utxos: Vec<server_api::Utxo> = utxos_slice
        .iter()
        .map(convert_to_native_utxo)
        .collect::<Result<Vec<_>, _>>()?;

    let mut pset = PartiallySignedTransaction::new_v2();

    // add inputs
    for utxo in &client_utxos {
        let input = pset::pset_input(pset::PsetInput {
            txid: utxo.txid,
            vout: utxo.vout,
            script_pub_key: utxo.script_pub_key.clone(),
            asset_commitment: Asset::Confidential(utxo.asset_commitment),
            value_commitment: Value::Confidential(utxo.value_commitment),
        });
        pset.add_input(input);
    }

    // add main output
    let main_output = pset::pset_output(pset::PsetOutput {
        address: send_address,
        asset: lbtc_asset_id,
        amount: send_amount,
    })?;
    pset.add_output(main_output);

    // add OP_RETURN output
    let op_return_script = Script::new_op_return(&op_return_data);
    let op_return_output = Output::from_txout(TxOut {
        asset: Asset::Explicit(lbtc_asset_id),
        value: Value::Explicit(0),
        nonce: Nonce::Null,
        script_pubkey: op_return_script,
        witness: TxOutWitness::default(),
    });
    pset.add_output(op_return_output);

    // calculate initial size and fee
    let initial_size = pset.extract_tx()?.weight() / 4; // vsize
    let mut fee_amount = (initial_size as f64 * fee_rate).ceil() as u64;

    // calculate and add change output
    let total_input: u64 = client_utxos.iter().map(|utxo| utxo.value).sum();
    let mut change_amount = total_input.saturating_sub(send_amount + fee_amount);
    if change_amount > 0 {
        let change_output = pset::pset_output(pset::PsetOutput {
            address: change_address.clone(),
            asset: lbtc_asset_id,
            amount: change_amount,
        })?;
        pset.add_output(change_output);
    }

    // recalculate fee based on final size
    let final_size = pset.extract_tx()?.weight() / 4; // vsize
    let new_fee_amount = (final_size as f64 * fee_rate).ceil() as u64;

    if new_fee_amount > fee_amount {
        // adjust fee and change if necessary
        fee_amount = new_fee_amount;
        change_amount = total_input.saturating_sub(send_amount + fee_amount);
        
        // update or remove change output
        if change_amount > 0 {
            if let Some(change_output) = pset.outputs_mut().last_mut() {
                if change_output.script_pubkey == change_address.script_pubkey() {
                    *change_output = pset::pset_output(pset::PsetOutput {
                        address: change_address,
                        asset: lbtc_asset_id,
                        amount: change_amount,
                    })?;
                }
            }
        } else {
            let change_script_pubkey = change_address.script_pubkey().clone();
            let outputs_len = pset.outputs().len();
            for i in (0..outputs_len).rev() {
                if pset.outputs()[i].script_pubkey == change_script_pubkey {
                    pset.remove_output(i);
                    break;
                }
            }
        }
    }

    // add fee output as the last output
    pset.add_output(pset::pset_network_fee(lbtc_asset_id, fee_amount));
    if let Some(last_output) = pset.outputs_mut().last_mut() {
        last_output.script_pubkey = Script::new();
    }

    // blinding
    let secp = Secp256k1::new();
    let mut rng = thread_rng();

    let mut input_secrets = HashMap::new();
    for (index, utxo) in client_utxos.iter().enumerate() {
        input_secrets.insert(index, TxOutSecrets {
            asset: lbtc_asset_id,
            asset_bf: AssetBlindingFactor::new(&mut rng),
            value: utxo.value,
            value_bf: ValueBlindingFactor::new(&mut rng),
        });
    }

    // blind all outputs exceptexcept the OP_RETURN and fee output (fee output is last output)
    let input_count = pset.inputs().len();
    for i in 0..pset.outputs().len() - 1 {
        if !pset.outputs()[i].script_pubkey.is_op_return() {
            let secret_key = secp256k1_zkp::SecretKey::new(&mut rng);
            let public_key = secp256k1_zkp::PublicKey::from_secret_key(&secp, &secret_key);
            pset.outputs_mut()[i].blinding_key = Some(PublicKey::from_slice(&public_key.serialize()).unwrap());
            pset.outputs_mut()[i].blinder_index = Some((i % input_count) as u32);
        }
    }    

    pset.blind_last(&mut rng, &secp, &input_secrets)?;
 
    // serialize the PSET
    let serialized_pset = serialize(&pset);
    let pset_base64 = base64::engine::general_purpose::STANDARD.encode(serialized_pset);

    Ok(pset_base64)
}

#[cfg(test)]
mod tests {
    use super::*;
    use elements::hex::ToHex;
    use std::ffi::CString;
    use elements::Address as ElementsAddress;
    use std::str::FromStr;
    use crate::UtxoFFI;  // Ma

    fn to_c_str(s: &str) -> *const c_char {
        CString::new(s).unwrap().into_raw() as *const c_char
    }

    fn create_utxo(txid: &str, vout: u32, value: u64, asset_id: &str) -> UtxoFFI {
        let address = ElementsAddress::from_str("VJL7JBzuzsfxSR8XbBJ9sDLKHyJLr5ccypeskmB4cgzNgyCvP2xYwfJXPqk9xPnQ1oA9RErgrYumsYF6").unwrap();
        let script_pub_key = address.script_pubkey();

        UtxoFFI {
            txid: CString::new(txid).unwrap().into_raw(),
            vout,
            value,
            script_pub_key: CString::new(script_pub_key.as_bytes().to_hex()).unwrap().into_raw(),
            asset_id: CString::new(asset_id).unwrap().into_raw(),
            asset_bf: CString::new("ed8b6d9fd55fab6cf51ae54b7e0bb1e7f1f6ef5b15ce45c8cbfc5d6a2d5b9795").unwrap().into_raw(),
            value_bf: CString::new("0bae106a80fc1b1eab8d5de3dff14498ee4d295268b43cc8c5ac3a6a01be85ef").unwrap().into_raw(),
            asset_commitment: CString::new("0b9e585cc4c2aa018796e00666e71438b71ea151bb1fdda852f9c23cd2fdc2968d").unwrap().into_raw(),
            value_commitment: CString::new("088124863e0a8c8037767b58be6218c7b5d5bac34b985a3fc110877cd900033753").unwrap().into_raw(),
        }
    }

    #[test]
    fn test_create_liquid_tx_with_op_return() {
        use elements::OutPoint;
        use elements::confidential::{Asset, Value};
        use std::ffi::CString;

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
    
        let result = create_liquid_tx_with_op_return_internal(
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

        assert!(result.is_ok(), "Error occurred: {:?}", result.err());
        let pset_base64 = result.unwrap();
        
        let pset_bytes = base64::engine::general_purpose::STANDARD.decode(pset_base64).expect("Failed to decode base64");
        let pset: PartiallySignedTransaction = elements::encode::deserialize(&pset_bytes).expect("Failed to deserialize PSET");        
        let tx = pset.extract_tx().expect("Failed to extract transaction from PSET");
    
        // verify the transaction structure
        assert_eq!(tx.version, 2, "Incorrect transaction version");
        assert_eq!(tx.input.len(), 2, "Incorrect number of inputs");
        assert!(tx.output.len() >= 3, "Incorrect number of outputs"); // At least 3: main output, OP_RETURN, and fee
    
        // verify inputs
        assert_eq!(tx.input[0].previous_output, OutPoint::new(elements::Txid::from_str("1234567890123456789012345678901234567890123456789012345678901234").unwrap(), 0));
        assert_eq!(tx.input[1].previous_output, OutPoint::new(elements::Txid::from_str("abcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcd").unwrap(), 1));
    
        // verify main output
        let main_output = &tx.output[0];
        assert!(matches!(main_output.value, Value::Confidential(_)), "Expected confidential value");
        assert!(matches!(main_output.asset, Asset::Confidential(_)), "Expected confidential asset");
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
            let change_output = &tx.output[2]; // Assuming change is the third output
            assert!(matches!(change_output.asset, Asset::Confidential(_)), "Expected confidential asset for change");
            assert!(matches!(change_output.value, Value::Confidential(_)), "Expected confidential value for change");
            
            // println!("Actual change script_pubkey: {:?}", change_output.script_pubkey);
            // println!("Expected change script_pubkey: {:?}", ElementsAddress::from_str("VJL7JBzuzsfxSR8XbBJ9sDLKHyJLr5ccypeskmB4cgzNgyCvP2xYwfJXPqk9xPnQ1oA9RErgrYumsYF6").unwrap().script_pubkey());
            
            assert_eq!(change_output.script_pubkey, ElementsAddress::from_str("VJL7JBzuzsfxSR8XbBJ9sDLKHyJLr5ccypeskmB4cgzNgyCvP2xYwfJXPqk9xPnQ1oA9RErgrYumsYF6").unwrap().script_pubkey());
        }

        // verify fee output is the last output
        assert!(tx.output.last().unwrap().is_fee(), "Fee output should be the last output");
    
        unsafe {
            let _ = CString::from_raw(send_address as *mut c_char);
            let _ = CString::from_raw(change_address as *mut c_char);
            let _ = CString::from_raw(op_return_data as *mut c_char);
        }
    }
}