use std::ffi::CStr;
use std::os::raw::c_char;
extern crate elements;
extern crate rand;

use base64::Engine;
use std::str::FromStr;

use elements::{Address, AssetId};
use elements::pset::{PartiallySignedTransaction, Output};
use elements::{Script, TxOut, TxOutWitness};
use elements::confidential::{Asset, Nonce, Value};
use elements::encode::serialize;

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

    // serialize the PSET
    let serialized_pset = serialize(&pset);
    let pset_base64 = base64::engine::general_purpose::STANDARD.encode(serialized_pset);

    Ok(pset_base64)
}