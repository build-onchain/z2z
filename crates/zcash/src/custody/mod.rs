//! Native effect inspection without signing, proof generation, or consensus claims.
//!
//! Checked metadata is not source finality, proof validity, signing approval, or
//! payment. The caller must persist the exact identities with its native plan and
//! durable business acknowledgements before any separate signing handoff.

pub(crate) mod pczt;

pub use pczt::inspect_pczt;

use ziquid_protocol::market::{Domain, Id, SourceOccurrence};
use orchard::{Address, keys::FullViewingKey};

/// Exact caller-enrolled context and already reserved physical inventory facts.
pub struct ExpectedNativeEffects<'a> {
    pub domain: &'a Domain,
    pub lock_time: u32,
    pub expiry_height: u32,
    pub fee: u64,
    pub inputs: &'a [ReservedNativeInput],
    pub outputs: &'a [ExpectedNativeOutput],
}

/// Trusted inventory facts, not a source-history proof or a shielded outpoint.
#[derive(Clone)]
pub struct ReservedNativeInput {
    pub inventory_note: Id,
    pub source_occurrence: SourceOccurrence,
    pub note_commitment: [u8; 32],
    pub nullifier: [u8; 32],
    pub value: u64,
    pub trusted_fvk: FullViewingKey,
}

/// Every nonzero recipient and change output must appear, including duplicates.
#[derive(Clone)]
pub struct ExpectedNativeOutput {
    pub recipient: Address,
    pub value: u64,
    pub kind: NativeOutputKind,
}

/// Borrowed, checked input identity without viewing or spend-authorizing keys.
pub struct CheckedNativeInput<'a> {
    input: &'a ReservedNativeInput,
}
impl CheckedNativeInput<'_> {
    pub fn inventory_note(&self) -> &Id {
        &self.input.inventory_note
    }
    pub fn source_occurrence(&self) -> &SourceOccurrence {
        &self.input.source_occurrence
    }
    pub fn note_commitment(&self) -> &Id {
        &self.input.note_commitment
    }
    pub fn nullifier(&self) -> &Id {
        &self.input.nullifier
    }
    pub fn value(&self) -> u64 {
        self.input.value
    }
}

/// Actual reconstructed and ciphertext-checked output, constructed only by
/// inspection. An owned output's nullifier uses its enrolled owning FVK.
pub struct CheckedNativeOutput {
    recipient: Address,
    value: u64,
    action_index: u32,
    note_commitment: Id,
    nullifier: Option<Id>,
}
impl CheckedNativeOutput {
    pub fn recipient(&self) -> &Address {
        &self.recipient
    }
    pub fn value(&self) -> u64 {
        self.value
    }
    pub fn action_index(&self) -> u32 {
        self.action_index
    }
    pub fn note_commitment(&self) -> &Id {
        &self.note_commitment
    }
    pub fn nullifier(&self) -> Option<&Id> {
        self.nullifier.as_ref()
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum NativeOutputKind {
    Recipient,
    Change,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CustodyError {
    Protocol(ziquid_protocol::market::ProtocolError),
    InvalidPczt,
    UnsupportedProfile,
    UnsupportedPool,
    ModifiableTransaction,
    GlobalMetadata,
    NetworkMarkerMismatch,
    InvalidExpectedEffects,
    MissingMetadata,
    NativeVerification,
    NativeParse,
    InputMismatch,
    OutputMismatch,
    ChangeOwnership,
    CiphertextMismatch,
    ValueBalanceMismatch,
    FeeMismatch,
    AmountOutOfRange,
    EffectExtraction,
    SighashEncoding,
    DummySpendKey,
}

impl core::fmt::Display for CustodyError {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(formatter, "native inspection rejected: {self:?}")
    }
}

impl std::error::Error for CustodyError {}

/// Only effects and policy-required note metadata were checked. Any supplied
/// proof or signatures remain unverified; absent anchors/witnesses are permitted
/// for V6 pre-authorization. No public constructor or generic verified flag.
pub struct UnsignedNativeInspection<'a> {
    domain: Domain,
    lock_time: u32,
    expiry_height: u32,
    fee: u64,
    exact_pczt_digest: Id,
    txid: Id,
    shielded_sighash: Id,
    inputs: &'a [ReservedNativeInput],
    outputs: Vec<CheckedNativeOutput>,
    expected_outputs: &'a [ExpectedNativeOutput],
}

impl UnsignedNativeInspection<'_> {
    pub fn domain(&self) -> &Domain {
        &self.domain
    }

    pub fn fee(&self) -> u64 {
        self.fee
    }

    pub fn exact_pczt_digest(&self) -> &[u8; 32] {
        &self.exact_pczt_digest
    }

    pub fn txid(&self) -> &[u8; 32] {
        &self.txid
    }

    pub fn shielded_sighash(&self) -> &[u8; 32] {
        &self.shielded_sighash
    }

    /// Native identities were matched to the PCZT. Source occurrence remains
    /// independent inventory testimony and must match the authenticated ledger.
    pub fn inputs(&self) -> impl ExactSizeIterator<Item = CheckedNativeInput<'_>> {
        self.inputs.iter().map(|input| CheckedNativeInput { input })
    }

    pub fn outputs(&self) -> &[CheckedNativeOutput] {
        &self.outputs
    }
    pub fn expected_outputs(&self) -> &[ExpectedNativeOutput] {
        self.expected_outputs
    }

    pub fn lock_time(&self) -> u32 {
        self.lock_time
    }

    pub fn expiry_height(&self) -> u32 {
        self.expiry_height
    }
}
