//! Original Overwinter V3 ZIP143 signature digests in raw BLAKE2b byte order.
//! Borrowed, fixed-size component caches are shared by every transaction signature.
//! Digest construction is not expiry/height/UTXO acceptance or script/proof checking.
//!
//! Streaming adaptation of zcash_primitives 0.30.1 `sighash_v4` (librustzcash
//! 97aefdc39a037da9c4f19a0e8a450d2c7932f53e), retaining the full signed-i32
//! hash-type semantics of zcashd 0512e9eb00f97172346e0fac854625d59771e4f7
//! `src/script/interpreter.cpp::SignatureHash`. Maintained serializers own every
//! outpoint, output and complete PHGR description encoding. No script rewriting.

/*
The MIT License (MIT)
Copyright (c) 2017-2019 Electric Coin Company
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

use blake2b_simd::{Params, State};
use corez::io::{self, Write};
use zcash_encoding::CompactSize;
use zcash_primitives::transaction::{Transaction, TxVersion};
use zcash_protocol::{consensus::BranchId, value::Zatoshis};

pub(crate) const ZERO_HASH: [u8; 32] = [0; 32];
const OUTPUTS_PERSONALIZATION: &[u8; 16] = b"ZcashOutputsHash";

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum OverwinterSighashError {
    UnsupportedVersion,
    UnsupportedBranch,
    IncompatibleTransaction,
    InputIndexOutOfRange,
    Serialization,
}

impl fmt::Display for OverwinterSighashError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::UnsupportedVersion => "not an exact Overwinter V3 transaction",
            Self::UnsupportedBranch => "not the Overwinter consensus branch",
            Self::IncompatibleTransaction => "transaction contains incompatible Overwinter fields",
            Self::InputIndexOutOfRange => "transparent input index is out of range",
            Self::Serialization => "Overwinter signature preimage serialization failed",
        })
    }
}

impl std::error::Error for OverwinterSighashError {}

pub(crate) fn check_overwinter_transaction(transaction: &Transaction) -> Result<(), OverwinterSighashError> {
    if transaction.version() != TxVersion::V3 {
        return Err(OverwinterSighashError::UnsupportedVersion);
    }
    if transaction.consensus_branch_id() != BranchId::Overwinter {
        return Err(OverwinterSighashError::UnsupportedBranch);
    }
    if transaction.sapling_bundle().is_some()
        || transaction.orchard_bundle().is_some()
        || transaction.ironwood_bundle().is_some()
        || transaction.sprout_bundle().is_some_and(|bundle| {
            bundle.joinsplits.is_empty()
                || bundle.joinsplits.iter().any(|description| description.groth_proof_bytes().is_some())
        })
    {
        return Err(OverwinterSighashError::IncompatibleTransaction);
    }
    Ok(())
}

/// An exact V3/Overwinter transaction and its four original component digests.
/// The enclosing boundary must canonically parse and exhaust its byte reader.
/// Construction rejects incompatible typed pools/proofs, not invalid expiry or
/// unavailable inputs/anchors. No transaction/preimage vectors are copied.
#[derive(Debug)]
pub struct OverwinterSignatureHash<'tx> {
    components: SignatureHashComponents<'tx>,
}

impl<'tx> OverwinterSignatureHash<'tx> {
    pub fn new(transaction: &'tx Transaction) -> Result<Self, OverwinterSighashError> {
        check_overwinter_transaction(transaction)?;
        Ok(Self { components: SignatureHashComponents::new(transaction)? })
    }

    /// Hashes the evaluator's WHOLE scriptCode and actual previous-output amount.
    /// All signed-i32 bytes are committed; only low5 and ANYONECANPAY select
    /// components. Actual signature bytes must be widened from u8, never i8.
    /// SINGLE without an output is a defined digest with zero hashOutputs.
    /// An invalid input index, including the JoinSplit sentinel, is an error.
    pub fn transparent(
        &self,
        input_index: usize,
        script_code: &[u8],
        previous_value: Zatoshis,
        raw_hash_type: i32,
    ) -> Result<[u8; 32], OverwinterSighashError> {
        self.components.transparent(input_index, script_code, previous_value, raw_hash_type, None)
    }

    /// Fixed ALL with no transparent suffix, including zero transparent inputs.
    /// The transaction-local crypto verifier derives this digest internally;
    /// callers cannot substitute an arbitrary authorization message.
    pub fn joinsplit(&self) -> [u8; 32] {
        self.components.shielded(None)
    }

    pub(crate) fn transaction(&self) -> &'tx Transaction {
        self.components.transaction
    }

}

// Four borrowed streaming ZIP143 components, also used by ZIP243. Exact
// version/pool guards belong to the public constructors, never this cache.
#[derive(Debug)]
pub(crate) struct SignatureHashComponents<'tx> {
    pub(crate) transaction: &'tx Transaction,
    prevouts: [u8; 32],
    sequences: [u8; 32],
    outputs: [u8; 32],
    joinsplits: [u8; 32],
}

impl<'tx> SignatureHashComponents<'tx> {
    pub(crate) fn new(transaction: &'tx Transaction) -> Result<Self, OverwinterSighashError> {
        let mut prevouts = HashWriter::new(b"ZcashPrevoutHash");
        let mut sequences = HashWriter::new(b"ZcashSequencHash");
        let mut outputs = HashWriter::new(OUTPUTS_PERSONALIZATION);
        let mut joinsplits = ZERO_HASH;
        let write_result = (|| -> io::Result<()> {
            if let Some(bundle) = transaction.transparent_bundle() {
                for input in &bundle.vin {
                    input.prevout().write(&mut prevouts)?;
                    sequences.0.update(&input.sequence().to_le_bytes());
                }
                for output in &bundle.vout {
                    output.write(&mut outputs)?;
                }
            }
            if let Some(bundle) = transaction.sprout_bundle() {
                let mut writer = HashWriter::new(b"ZcashJSplitsHash");
                for description in &bundle.joinsplits {
                    description.write(&mut writer)?;
                }
                writer.0.update(&bundle.joinsplit_pubkey);
                joinsplits = writer.finish();
            }
            Ok(())
        })();
        write_result.map_err(|_| OverwinterSighashError::Serialization)?;
        Ok(Self {
            transaction, prevouts: prevouts.finish(), sequences: sequences.finish(),
            outputs: outputs.finish(), joinsplits,
        })
    }

    pub(crate) fn transparent(
        &self,
        input_index: usize,
        script_code: &[u8],
        previous_value: Zatoshis,
        raw_hash_type: i32,
        sapling: Option<(&[u8; 32], &[u8; 32])>,
    ) -> Result<[u8; 32], OverwinterSighashError> {
        let bundle = self.transaction.transparent_bundle()
            .ok_or(OverwinterSighashError::InputIndexOutOfRange)?;
        let input = bundle.vin.get(input_index).ok_or(OverwinterSighashError::InputIndexOutOfRange)?;
        let single_output;
        let outputs = match raw_hash_type & 0x1f {
            2 => &ZERO_HASH,
            3 => if let Some(output) = bundle.vout.get(input_index) {
                let mut writer = HashWriter::new(OUTPUTS_PERSONALIZATION);
                output.write(&mut writer).map_err(|_| OverwinterSighashError::Serialization)?;
                single_output = writer.finish();
                &single_output
            } else {
                &ZERO_HASH
            },
            _ => &self.outputs,
        };
        let mut writer = self.prefix(raw_hash_type, outputs, sapling);
        let write_result = (|| -> io::Result<()> {
            input.prevout().write(&mut writer)?;
            CompactSize::write(&mut writer, script_code.len())?;
            writer.write_all(script_code)?;
            writer.write_all(&previous_value.to_i64_le_bytes())?;
            writer.write_all(&input.sequence().to_le_bytes())
        })();
        write_result.map_err(|_| OverwinterSighashError::Serialization)?;
        Ok(writer.finish())
    }

    pub(crate) fn shielded(&self, sapling: Option<(&[u8; 32], &[u8; 32])>) -> [u8; 32] {
        self.prefix(1, &self.outputs, sapling).finish()
    }

    fn prefix(&self, raw_hash_type: i32, outputs: &[u8; 32], sapling: Option<(&[u8; 32], &[u8; 32])>) -> HashWriter {
        let mut personalization = [0; 16];
        personalization[..12].copy_from_slice(b"ZcashSigHash");
        personalization[12..].copy_from_slice(&u32::from(self.transaction.consensus_branch_id()).to_le_bytes());
        let mut writer = HashWriter::new(&personalization);
        let hash = &mut writer.0;
        hash.update(&self.transaction.version().header().to_le_bytes());
        hash.update(&self.transaction.version().version_group_id().to_le_bytes());
        let anyonecanpay = raw_hash_type & 0x80 != 0;
        hash.update(if anyonecanpay { &ZERO_HASH } else { &self.prevouts });
        hash.update(if anyonecanpay || matches!(raw_hash_type & 0x1f, 2 | 3) { &ZERO_HASH } else { &self.sequences });
        hash.update(outputs);
        hash.update(&self.joinsplits);
        if let Some((spends, outputs)) = sapling {
            hash.update(spends);
            hash.update(outputs);
        }
        hash.update(&self.transaction.lock_time().to_le_bytes());
        hash.update(&u32::from(self.transaction.expiry_height()).to_le_bytes());
        if sapling.is_some() {
            hash.update(&self.transaction.sapling_value_balance().to_i64_le_bytes());
        }
        hash.update(&raw_hash_type.to_le_bytes());
        writer
    }
}

// Explicit adapter keeps corez::Write available even when blake2b_simd's std
// feature is disabled in the independent guests. The serializer owns encoding.
pub(crate) struct HashWriter(pub(crate) State);

impl HashWriter {
    pub(crate) fn new(personalization: &[u8; 16]) -> Self {
        Self(Params::new().hash_length(32).personal(personalization).to_state())
    }

    pub(crate) fn finish(self) -> [u8; 32] {
        let mut digest = [0; 32];
        digest.copy_from_slice(self.0.finalize().as_bytes());
        digest
    }
}

impl Write for HashWriter {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        self.0.update(bytes);
        Ok(bytes.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}
