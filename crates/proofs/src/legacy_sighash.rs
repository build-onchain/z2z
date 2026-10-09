//! Original pre-Overwinter Zcash transparent signature hash, in raw SHA256d
//! byte order. Hashing is not script authorization, UTXO/source validity, or
//! JoinSplit-proof validation. The caller supplies the evaluator's whole script.
//!
//! Direct port of the MIT Zcash `CTransactionSignatureSerializer` and legacy
//! `SignatureHash` at commit 0512e9eb00f97172346e0fac854625d59771e4f7:
//! <https://github.com/zcash/zcash/blob/0512e9eb00f97172346e0fac854625d59771e4f7/src/script/interpreter.cpp#L970-L1050>
//! <https://github.com/zcash/zcash/blob/0512e9eb00f97172346e0fac854625d59771e4f7/src/script/interpreter.cpp#L1246-L1261>
//! JoinSplit encoding and signed null outputs:
//! <https://github.com/zcash/zcash/blob/0512e9eb00f97172346e0fac854625d59771e4f7/src/primitives/transaction.h>
//! Unlike Bitcoin, invalid indices/SINGLE outputs are errors, not constant ONE;
//! scriptCode is not subjected to FindAndDelete or CODESEPARATOR stripping.

/*
Copyright (c) 2009-2010 Satoshi Nakamoto
Copyright (c) 2009-2014 The Bitcoin Core developers
Copyright (c) 2016-2019 The Zcash developers
Copyright (c) 2009-2019 The Bitcoin Core developers
Copyright (c) 2009-2019 Bitcoin Developers

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in
all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
THE SOFTWARE.
*/

use std::fmt;

use corez::io::Write;
use zcash_encoding::CompactSize;
use zcash_primitives::transaction::{Transaction, TxVersion};
use zcash_transparent::util::sha256d::HashWriter;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum LegacySighashError {
    UnsupportedVersion,
    IncompatibleTransaction,
    InputIndexOutOfRange,
    MissingSingleOutput,
    Serialization,
}

impl fmt::Display for LegacySighashError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::UnsupportedVersion => "not a legal pre-Overwinter Sprout version",
            Self::IncompatibleTransaction => "transaction contains incompatible legacy fields",
            Self::InputIndexOutOfRange => "transparent input index is out of range",
            Self::MissingSingleOutput => "no matching output for legacy SIGHASH_SINGLE",
            Self::Serialization => "legacy signature preimage serialization failed",
        })
    }
}

impl std::error::Error for LegacySighashError {}

/// Hashes an actual typed legacy transaction with O(1) auxiliary state and no
/// transaction/bundle clone or preimage allocation. Preserve canonical parsing
/// and reader exhaustion at the enclosing input boundary; this helper rejects
/// incompatible typed shapes but does not establish complete format/consensus
/// validity. All legal Sprout version numbers retain their original headers.
///
/// `raw_hash_type` is committed as all four original signed-i32 LE bytes. Only
/// its low five bits (NONE=2, SINGLE=3, otherwise ALL-like) and bit 0x80 select
/// fields. An actual signature suffix must be widened from u8, not i8.
///
/// `input_index` is always a transparent input. It never accepts the distinct
/// `NOT_AN_INPUT` JoinSplit-authorization sentinel, including `usize::MAX`.
/// `script_code` is hashed byte-for-byte, including pushed signature/data bytes;
/// evaluation of disabled opcodes belongs to the script evaluator, not hashing.
/// Every hash type commits every complete PHGR JoinSplit and its public key;
/// only the JoinSplit signature's serialized 64-byte slot is replaced by zeros.
pub fn legacy_signature_hash(
    transaction: &Transaction,
    input_index: usize,
    script_code: &[u8],
    raw_hash_type: i32,
) -> Result<[u8; 32], LegacySighashError> {
    let version = check_legacy_transaction(transaction)?;
    hash_legacy_transaction(transaction, version, SignatureMode::Transparent { input_index, script_code, raw_hash_type })
}

pub(crate) fn check_legacy_transaction(transaction: &Transaction) -> Result<u32, LegacySighashError> {
    let version = match transaction.version() {
        TxVersion::Sprout(version @ 1..=0x7fff_ffff) => version,
        _ => return Err(LegacySighashError::UnsupportedVersion),
    };
    if u32::from(transaction.expiry_height()) != 0
        || transaction.sapling_bundle().is_some()
        || transaction.orchard_bundle().is_some()
        || transaction.ironwood_bundle().is_some()
        || transaction.sprout_bundle().is_some_and(|bundle| {
            version == 1
                || bundle.joinsplits.is_empty()
                || bundle.joinsplits.iter().any(|description| description.groth_proof_bytes().is_some())
        })
    {
        return Err(LegacySighashError::IncompatibleTransaction);
    }
    Ok(version)
}

/// Fixed original NOT_AN_INPUT + SIGHASH_ALL recipe. The crypto verifier checks
/// the complete typed shape first with `check_legacy_transaction`; this internal
/// serializer is not an alternative acceptance/format-validation interface.
pub(crate) fn legacy_joinsplit_signature_hash(transaction: &Transaction) -> Result<[u8; 32], LegacySighashError> {
    let version = match transaction.version() {
        TxVersion::Sprout(version @ 1..=0x7fff_ffff) => version,
        _ => return Err(LegacySighashError::UnsupportedVersion),
    };
    hash_legacy_transaction(transaction, version, SignatureMode::JoinSplitAll)
}

enum SignatureMode<'a> {
    Transparent { input_index: usize, script_code: &'a [u8], raw_hash_type: i32 },
    JoinSplitAll,
}

fn hash_legacy_transaction(
    transaction: &Transaction,
    version: u32,
    mode: SignatureMode<'_>,
) -> Result<[u8; 32], LegacySighashError> {
    let sprout = transaction.sprout_bundle();
    let transparent = transaction.transparent_bundle();
    let all_inputs = transparent.map_or(&[][..], |bundle| bundle.vin.as_slice());
    let all_outputs = transparent.map_or(&[][..], |bundle| bundle.vout.as_slice());
    let (input_index, script_code, raw_hash_type) = match mode {
        SignatureMode::Transparent { input_index, script_code, raw_hash_type } => (Some(input_index), script_code, raw_hash_type),
        SignatureMode::JoinSplitAll => (None, &[][..], 1),
    };
    let (first_index, inputs) = if let Some(index) = input_index {
        let selected = all_inputs.get(index).ok_or(LegacySighashError::InputIndexOutOfRange)?;
        if raw_hash_type & 0x80 != 0 { (index, core::slice::from_ref(selected)) } else { (0, all_inputs) }
    } else {
        (0, all_inputs)
    };
    let base = raw_hash_type & 0x1f;
    let single_output = match (base, input_index) {
        (3, Some(index)) => Some((index, all_outputs.get(index).ok_or(LegacySighashError::MissingSingleOutput)?)),
        _ => None,
    };

    let mut writer = HashWriter::default();
    let write_result = (|| -> corez::io::Result<()> {
        writer.write_all(&version.to_le_bytes())?;
        CompactSize::write(&mut writer, inputs.len())?;
        for (offset, input) in inputs.iter().enumerate() {
            let is_selected = input_index == Some(first_index + offset);
            input.prevout().write(&mut writer)?;
            let script = if is_selected { script_code } else { &[] };
            CompactSize::write(&mut writer, script.len())?;
            writer.write_all(script)?;
            let sequence = if !is_selected && matches!(base, 2 | 3) { 0 } else { input.sequence() };
            writer.write_all(&sequence.to_le_bytes())?;
        }
        if let Some((index, output)) = single_output {
            // get(index) above proves index + 1 cannot overflow.
            CompactSize::write(&mut writer, index + 1)?;
            for _ in 0..index {
                // Signed CTxOut::SetNull value -1, then empty script. Zatoshis
                // cannot represent this consensus placeholder; stream it.
                writer.write_all(&[0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0])?;
            }
            output.write(&mut writer)?;
        } else if base == 2 {
            CompactSize::write(&mut writer, 0)?;
        } else {
            CompactSize::write(&mut writer, all_outputs.len())?;
            for output in all_outputs {
                output.write(&mut writer)?;
            }
        }
        writer.write_all(&transaction.lock_time().to_le_bytes())?;
        if version >= 2 {
            CompactSize::write(&mut writer, sprout.map_or(0, |bundle| bundle.joinsplits.len()))?;
            if let Some(bundle) = sprout {
                for description in &bundle.joinsplits {
                    description.write(&mut writer)?;
                }
                writer.write_all(&bundle.joinsplit_pubkey)?;
                writer.write_all(&[0; 64])?;
            }
        }
        writer.write_all(&raw_hash_type.to_le_bytes())
    })();
    write_result.map_err(|_| LegacySighashError::Serialization)?;
    Ok(writer.into_hash().into())
}

#[cfg(test)]
mod tests {
    use super::*;
    use zcash_protocol::consensus::BranchId;

    #[test]
    fn fixed_joinsplit_all_hashes_zero_vin_and_absent_transparent_bundle() {
        // Hand-authored transaction: version2, zero vin, one value1/script51
        // output, locktime7, zero JoinSplits. Independent sentinel-ALL preimage
        // appends 01000000. Literal SHA256d computed independently, not via this
        // module's serializer or a fake zero-vin accepted JoinSplit fixture.
        let zero_vin = [2, 0, 0, 0, 0, 1, 1, 0, 0, 0, 0, 0, 0, 0, 1, 0x51, 7, 0, 0, 0, 0];
        let transaction = Transaction::read(&zero_vin[..], BranchId::Sprout).unwrap();
        assert_eq!(check_legacy_transaction(&transaction), Ok(2));
        assert_eq!(legacy_joinsplit_signature_hash(&transaction), Ok([
            0xca, 0x6f, 0xfe, 0x85, 0xf8, 0x81, 0x57, 0xc7, 0xeb, 0xff, 0xc7, 0x45, 0x97, 0x6c, 0x15, 0x77,
            0xe2, 0x9e, 0x4e, 0x6c, 0xf5, 0xfe, 0x33, 0x72, 0x6b, 0xde, 0x5f, 0x96, 0x53, 0xfd, 0x32, 0x86,
        ]));
        assert_eq!(legacy_signature_hash(&transaction, 0, &[], 1), Err(LegacySighashError::InputIndexOutOfRange));

        // No vin or vout means transparent_bundle=None; both empty counts still
        // enter the hash. Preimage: 020000000000070000000001000000.
        let no_transparent = [2, 0, 0, 0, 0, 0, 7, 0, 0, 0, 0];
        let transaction = Transaction::read(&no_transparent[..], BranchId::Sprout).unwrap();
        assert!(transaction.transparent_bundle().is_none());
        assert_eq!(check_legacy_transaction(&transaction), Ok(2));
        assert_eq!(legacy_joinsplit_signature_hash(&transaction), Ok([
            0x2f, 0x4c, 0x91, 0x10, 0x90, 0x86, 0x34, 0x9b, 0x68, 0x4c, 0x9c, 0x1b, 0x13, 0x0a, 0x3b, 0x0e,
            0x9c, 0xdc, 0x48, 0xd2, 0x07, 0xa8, 0x31, 0x01, 0x73, 0xfd, 0x0b, 0x62, 0xcd, 0x18, 0xdd, 0xc4,
        ]));
        assert_eq!(legacy_signature_hash(&transaction, usize::MAX, &[], 1), Err(LegacySighashError::InputIndexOutOfRange));
    }
}
