//! Exact Sapling V4 ZIP243 signature digests in raw BLAKE2b byte order.
//! This is a digest subrelation, not proof/signature verification or ledger admission.
//!
//! Streaming adaptation of zcash_primitives 0.30.1 `sighash_v4` (librustzcash
//! 97aefdc39a037da9c4f19a0e8a450d2c7932f53e), retaining all signed-i32 hash-type
//! bits from zcashd 0512e9eb00f97172346e0fac854625d59771e4f7
//! `src/script/interpreter.cpp::SignatureHash`. ZIP243: https://zips.z.cash/zip-0243.
//! Maintained serializers own outpoints, outputs and complete Groth16 JoinSplits.

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

use zcash_primitives::transaction::{
    Transaction, TxVersion, components::sapling::temporary_zcashd_write_output_v4,
};
use zcash_protocol::value::Zatoshis;

use crate::overwinter::{HashWriter, OverwinterSighashError, SignatureHashComponents, ZERO_HASH};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SaplingSighashError {
    UnsupportedVersion,
    UnsupportedBranch,
    IncompatibleTransaction,
    InputIndexOutOfRange,
    Serialization,
}

impl fmt::Display for SaplingSighashError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::UnsupportedVersion => "not an exact Sapling V4 transaction",
            Self::UnsupportedBranch => "transaction version is not valid in this consensus branch",
            Self::IncompatibleTransaction => "transaction contains incompatible Sapling V4 fields",
            Self::InputIndexOutOfRange => "transparent input index is out of range",
            Self::Serialization => "Sapling signature preimage serialization failed",
        })
    }
}

impl std::error::Error for SaplingSighashError {}

pub(crate) fn check_sapling_transaction(transaction: &Transaction) -> Result<(), SaplingSighashError> {
    if transaction.version() != TxVersion::V4 {
        return Err(SaplingSighashError::UnsupportedVersion);
    }
    if !TxVersion::V4.valid_in_branch(transaction.consensus_branch_id()) {
        return Err(SaplingSighashError::UnsupportedBranch);
    }
    if transaction.orchard_bundle().is_some()
        || transaction.ironwood_bundle().is_some()
        || transaction.sprout_bundle().is_some_and(|bundle| {
            bundle.joinsplits.is_empty()
                || bundle.joinsplits.iter().any(|description| description.groth_proof_bytes().is_none())
        })
        || transaction.sapling_bundle().is_some_and(|bundle| {
            bundle.shielded_spends().is_empty() && bundle.shielded_outputs().is_empty()
        })
    {
        return Err(SaplingSighashError::IncompatibleTransaction);
    }
    Ok(())
}

/// Borrows an exact V4 transaction and caches its six ZIP243 component digests.
/// The enclosing byte boundary must exhaust its reader and check canonical
/// round-trip equality: the maintained typed reader normalizes absent Sapling
/// valueBalance to zero. Expiry, UTXO/anchor availability, proof/signature validity
/// and contextual transaction acceptance are deliberately not digest predicates.
#[derive(Debug)]
pub struct SaplingSignatureHash<'tx> {
    components: SignatureHashComponents<'tx>,
    spends: [u8; 32],
    outputs: [u8; 32],
}

impl<'tx> SaplingSignatureHash<'tx> {
    pub fn new(transaction: &'tx Transaction) -> Result<Self, SaplingSighashError> {
        check_sapling_transaction(transaction)?;
        let components = SignatureHashComponents::new(transaction)
            .map_err(|_| SaplingSighashError::Serialization)?;
        let mut hashes = Self { components, spends: ZERO_HASH, outputs: ZERO_HASH };
        if let Some(bundle) = hashes.transaction().sapling_bundle() {
            if !bundle.shielded_spends().is_empty() {
                let mut writer = HashWriter::new(b"ZcashSSpendsHash");
                for spend in bundle.shielded_spends() {
                    writer.0.update(&spend.cv().to_bytes());
                    // Pinned Scalar::to_bytes is exactly PrimeField::to_repr.
                    writer.0.update(&spend.anchor().to_bytes());
                    writer.0.update(spend.nullifier().as_ref());
                    writer.0.update(&<[u8; 32]>::from(*spend.rk()));
                    writer.0.update(spend.zkproof());
                }
                hashes.spends = writer.finish();
            }
            if !bundle.shielded_outputs().is_empty() {
                let mut writer = HashWriter::new(b"ZcashSOutputHash");
                for output in bundle.shielded_outputs() {
                    temporary_zcashd_write_output_v4(&mut writer, output)
                        .map_err(|_| SaplingSighashError::Serialization)?;
                }
                hashes.outputs = writer.finish();
            }
        }
        Ok(hashes)
    }

    /// Hashes the whole evaluator scriptCode and actual previous-output amount.
    /// Only low5 and ANYONECANPAY select components; all signed-i32 bits commit.
    /// Actual signature bytes widen from u8, never i8. Missing SINGLE output
    /// means zero hashOutputs; a missing input (including the sentinel) rejects.
    pub fn transparent(
        &self,
        input_index: usize,
        script_code: &[u8],
        previous_value: Zatoshis,
        raw_hash_type: i32,
    ) -> Result<[u8; 32], SaplingSighashError> {
        self.components.transparent(
            input_index, script_code, previous_value, raw_hash_type,
            Some((&self.spends, &self.outputs)),
        ).map_err(|error| match error {
            OverwinterSighashError::InputIndexOutOfRange => SaplingSighashError::InputIndexOutOfRange,
            _ => SaplingSighashError::Serialization,
        })
    }

    /// Fixed ALL without a transparent suffix, for JoinSplit, SpendAuth and
    /// binding authorization of this same transaction. No message override.
    pub fn shielded(&self) -> [u8; 32] {
        self.components.shielded(Some((&self.spends, &self.outputs)))
    }

    pub(crate) fn transaction(&self) -> &'tx Transaction {
        self.components.transaction
    }
}
