use orchard::{Anchor, note::TransmittedNoteCiphertext, pczt::Bundle};
use zcash_primitives::transaction::Transaction;

fn same_ciphertext(a: &TransmittedNoteCiphertext, b: &TransmittedNoteCiphertext) -> bool {
    a.epk_bytes == b.epk_bytes && a.enc_ciphertext == b.enc_ciphertext && a.out_ciphertext == b.out_ciphertext
}

// Complete action order/ciphertexts; anchor is an independent V6 input, not txid.
pub(crate) fn matches(private: &Bundle, transaction: &Transaction, anchor: Anchor) -> bool {
    let Some(finished) = transaction.ironwood_bundle() else { return false; };
    let Ok(value) = i64::try_from(*private.value_sum()) else { return false; };
    if *private.bundle_version() != finished.bundle_version() || private.flag_byte() != finished.flag_byte()
        || finished.anchor() != &anchor || value != i64::from(*finished.value_balance())
        || private.actions().len() != finished.actions().len() { return false; }
    private.actions().iter().zip(finished.actions()).all(|(left, right)| {
        left.cv_net().to_bytes() == right.cv_net().to_bytes() && left.spend().nullifier() == right.nullifier()
            && left.spend().rk() == right.rk() && left.output().cmx() == right.cmx()
            && same_ciphertext(left.output().encrypted_note(), right.encrypted_note())
    })
}
