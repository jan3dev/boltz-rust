use elements::{Transaction, encode::VarInt};

const FEE_RATE: f64 = 0.1;
const FEE_RATE_LOWBALL: f64 = 0.01;

// Constants for lowball estimation
const WEIGHT_FIXED: usize = 44;
const WEIGHT_VIN_SINGLE_SIG: usize = 367;
const WEIGHT_VIN_MULTI_SIG: usize = 526;
const WEIGHT_VOUT: usize = 4810;
const WEIGHT_FEE: usize = 178;

/// Calculate simplified weight for lowball fees
fn estimate_weight(
    single_sig_inputs: usize,
    multi_sig_inputs: usize,
    blinded_outputs: usize,
) -> usize {
    let base_weight = WEIGHT_FIXED
        + WEIGHT_VIN_SINGLE_SIG * single_sig_inputs
        + WEIGHT_VIN_MULTI_SIG * multi_sig_inputs
        + WEIGHT_VOUT * blinded_outputs
        + WEIGHT_FEE;
    
    // Apply confidential discounts
    let value_discount = (33 - 9) * 4 * blinded_outputs;
    let nonce_discount = (33 - 1) * 4 * blinded_outputs;
    base_weight.saturating_sub(value_discount + nonce_discount)
}

/// Calculate the weight of a transaction, following Elements' implementation
fn scaled_size(tx: &Transaction, scale_factor: usize) -> usize {
    let witness_flag = tx.has_witness();

    let input_weight = tx.input.iter().map(|input| {
        scale_factor * (
            32 + 4 + 4 + // output + nSequence
            VarInt(input.script_sig.len() as u64).size() +
            input.script_sig.len() + if input.has_issuance() {
                64 +
                input.asset_issuance.amount.encoded_length() +
                input.asset_issuance.inflation_keys.encoded_length()
            } else {
                0
            }
        ) + if witness_flag {
            // Add witness data weight calculations
            let amt_prf_len = input.witness.amount_rangeproof.as_ref()
                .map(|x| x.len()).unwrap_or(0);
            let keys_prf_len = input.witness.inflation_keys_rangeproof.as_ref()
                .map(|x| x.len()).unwrap_or(0);
            
            VarInt(amt_prf_len as u64).size() +
            amt_prf_len +
            VarInt(keys_prf_len as u64).size() +
            keys_prf_len +
            // Add script witness weight
            VarInt(input.witness.script_witness.len() as u64).size() +
            input.witness.script_witness.iter().map(|wit|
                VarInt(wit.len() as u64).size() +
                wit.len()
            ).sum::<usize>() +
            // Add pegin witness weight
            VarInt(input.witness.pegin_witness.len() as u64).size() +
            input.witness.pegin_witness.iter().map(|wit|
                VarInt(wit.len() as u64).size() +
                wit.len()
            ).sum::<usize>()
        } else {
            0
        }
    }).sum::<usize>();

    let output_weight = tx.output.iter().map(|output| {
        scale_factor * (
            output.asset.encoded_length() +
            output.value.encoded_length() +
            output.nonce.encoded_length() +
            VarInt(output.script_pubkey.len() as u64).size() +
            output.script_pubkey.len()
        ) + if witness_flag {
            let range_prf_len = output.witness.rangeproof_len();
            let surj_prf_len = output.witness.surjectionproof_len();
            VarInt(surj_prf_len as u64).size() +
            surj_prf_len +
            VarInt(range_prf_len as u64).size() +
            range_prf_len
        } else {
            0
        }
    }).sum::<usize>();

    scale_factor * (
        4 + // version
        4 + // locktime
        VarInt(tx.input.len() as u64).size() +
        VarInt(tx.output.len() as u64).size() +
        1  // segwit flag byte
    ) + input_weight + output_weight
}

/// Calculate the "discount weight" following Elements' implementation
fn discount_weight(tx: &Transaction) -> usize {
    let mut weight = scaled_size(tx, 4);

    for out in tx.output.iter() {
        let rp_len = out.witness.rangeproof_len();
        let sp_len = out.witness.surjectionproof_len();
        let witness_weight = VarInt(sp_len as u64).size() + sp_len + 
                           VarInt(rp_len as u64).size() + rp_len;
        weight -= witness_weight.saturating_sub(2); // explicit transactions have 1 byte for each empty proof
        if out.value.is_confidential() {
            weight -= (33 - 9) * 4;
        }
        if out.nonce.is_confidential() {
            weight -= (33 - 1) * 4;
        }
    }

    weight
}

/// Calculate the network fee based on either estimated weight (lowball) or actual transaction weight (discountCT)
pub fn expected_network_fee(
    tx: &Transaction,
    single_sig_inputs: usize,
    multi_sig_inputs: usize,
    blinded_outputs: usize,
    is_lowball: bool,
) -> u64 {
    if is_lowball {
        let weight = estimate_weight(single_sig_inputs, multi_sig_inputs, blinded_outputs);
        let vsize = (weight + 3) / 4;
        (vsize as f64 * FEE_RATE_LOWBALL).ceil() as u64
    } else {
        let vsize = (discount_weight(tx) + 4 - 1) / 4;
        (vsize as f64 * FEE_RATE).ceil() as u64
    }
}
