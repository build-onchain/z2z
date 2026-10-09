#![forbid(unsafe_code)]
//! PostgreSQL safety state and retained ordinary-business acknowledgement journals.
//! Authenticated local inputs prove storage safety, not source acquisition or chain finality.

use ed25519_dalek::SigningKey;
use ziquid_protocol::market::{
    AllocationKind, ChainObservation, Decision, Domain, FundingClaim, Id, NativeIntentKind,
    ObservationEnvironment, Operation, SourceOccurrence,
};
use crate::database::DatabaseConfig;

mod codec;
mod replica;
mod store;
mod target;
mod wire;
pub use codec::MAX_JOURNAL_BYTES;
pub use replica::Replica;
pub use store::Ledger;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PairPolicy {
    pub domain: Domain,
    pub environment: ObservationEnvironment,
    pub source_policy: Id,
    pub history_anchor: Id,
    pub minimum_confirmations: u32,
    pub receiver: [u8; 43],
    pub inventory_scope: Id,
    pub sponsor_scope: Id,
    pub source_producer: Id,
    pub inventory_producer: Id,
    pub target_observer: Id,
    pub target_admin: Id,
    pub roster: [Id; 3],
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct WriterFence {
    pub pair: Id,
    pub generation: u64,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SourceEffect {
    Deposit { claimant: Id, credit_intent: Id },
    Change { parent_intent: Id },
    Unclaimed,
    HistoryGap,
    Reorged,
    Unknown,
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SourceFacts {
    pub domain: Domain,
    pub provenance: ObservationEnvironment,
    pub occurrence: SourceOccurrence,
    pub receiver: [u8; 43],
    pub value: u64,
    pub block: Id,
    pub height: u64,
    pub confirmations: u32,
    pub history_anchor: Id,
    pub policy: Id,
    pub effect: SourceEffect,
}
impl SourceFacts {
    pub fn digest(&self) -> Result<Id, LedgerError> {
        Ok(codec::hash(&codec::source_bytes(self)?))
    }
    pub fn signing_bytes(&self) -> Result<[u8; 64], LedgerError> {
        Ok(codec::signing(
            b"KERB_SOURCE_PRODUCER_V1",
            &codec::source_bytes(self)?,
        ))
    }
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SignedSourceFacts {
    pub facts: SourceFacts,
    pub signature: [u8; 64],
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum InventoryOrigin {
    Deposit,
    Change { parent_intent: Id },
    Sponsor,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum InventoryCondition {
    Spendable,
    HistoryGap,
    Reorged,
    Unknown,
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct InventoryFacts {
    pub domain: Domain,
    pub provenance: ObservationEnvironment,
    pub note: Id,
    pub occurrence: SourceOccurrence,
    pub note_commitment: Id,
    pub nullifier: Id,
    pub receiver: [u8; 43],
    pub value: u64,
    pub scope: Id,
    pub control: Id,
    pub origin: InventoryOrigin,
    pub condition: InventoryCondition,
    pub history_anchor: Id,
}
impl InventoryFacts {
    pub fn signing_bytes(&self) -> Result<[u8; 64], LedgerError> {
        Ok(codec::signing(
            b"KERB_INVENTORY_PRODUCER_V2",
            &codec::inventory_bytes(self)?,
        ))
    }
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SignedInventoryFacts {
    pub facts: InventoryFacts,
    pub signature: [u8; 64],
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TargetFacts {
    pub decision: Decision,
    pub observation: ChainObservation,
}
impl TargetFacts {
    pub fn signing_bytes(&self) -> Result<[u8; 64], LedgerError> {
        Ok(codec::signing(
            b"KERB_TARGET_OBSERVER_V1",
            &codec::target_bytes(self)?,
        ))
    }
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SignedTargetFacts {
    pub facts: TargetFacts,
    pub signature: [u8; 64],
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum TargetHoldEvidence {
    Prepared {
        prepare: SignedTargetFacts,
    },
    Locked {
        anchor: SignedTargetFacts,
        lock_transaction: Id,
        lock_slot: u64,
    },
}
impl TargetHoldEvidence {
    pub(crate) fn anchor(&self) -> &SignedTargetFacts {
        match self {
            Self::Prepared { prepare } => prepare,
            Self::Locked { anchor, .. } => anchor,
        }
    }
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TargetHoldBinding {
    pub domain: Domain,
    pub hold_business: Id,
    pub maximum_base: u64,
    pub expected_chunks: u32,
    pub refund_token: Id,
    pub evidence: TargetHoldEvidence,
    pub epoch_version: u64,
    pub signature: [u8; 64],
}
impl TargetHoldBinding {
    pub fn signing_bytes(&self) -> Result<[u8; 64], LedgerError> {
        Ok(codec::signing(
            b"KERB_TARGET_HOLD_BINDING_V1",
            &codec::target_binding_bytes(self)?,
        ))
    }
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TargetAuthorization {
    pub hold: Id,
    pub portion: Id,
    pub decision: Decision,
    pub payload: Vec<u8>,
    pub accounts: Vec<Id>,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PortionSpec {
    pub portion: Id,
    pub offset: u64,
    pub amount: u64,
    pub kind: AllocationKind,
    pub native_recipient: [u8; 43],
    pub spl_recipient: Id,
    pub target_base_offset: u64,
    pub target_base_amount: u64,
    pub fill_fence: Id,
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AllocationPlan {
    pub hold: Id,
    pub allocation: Id,
    pub portions: Vec<PortionSpec>,
    pub chunks: Vec<Id>,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ChangeOutput {
    pub note: Id,
    pub action_index: u32,
    pub note_commitment: Id,
    pub nullifier: Id,
    pub receiver: [u8; 43],
    pub value: u64,
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NativePlan {
    pub hold: Id,
    pub portion: Id,
    pub kind: NativeIntentKind,
    pub recipient: [u8; 43],
    pub amount: u64,
    pub inventory_scope: Id,
    pub inputs: Vec<Id>,
    pub fee_inputs: Vec<Id>,
    pub change: Vec<ChangeOutput>,
    pub fee: u64,
    pub nonce: Id,
    pub pczt_digest: Id,
    pub sighash: Id,
    pub transaction: Id,
}
impl NativePlan {
    pub fn native_intent(
        &self,
        operation: Operation,
    ) -> Result<ziquid_protocol::market::NativeIntent, LedgerError> {
        let intent = ziquid_protocol::market::NativeIntent {
            operation,
            kind: self.kind,
            recipient: self.recipient,
            amount: self.amount,
            inventory_scope: self.inventory_scope,
        };
        if operation.entity != self.hold
            || operation.portion != self.portion
            || operation.transition != ziquid_protocol::market::Transition::PrepareNative
            || operation.effects != intent.effects_digest().map_err(|_| LedgerError::Protocol)?
        {
            return Err(LedgerError::Conflict);
        }
        Ok(intent)
    }
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NativeFacts {
    pub domain: Domain,
    pub provenance: ObservationEnvironment,
    pub intent: Id,
    pub transaction: Id,
    pub inputs: Vec<Id>,
    pub recipient: [u8; 43],
    pub amount: u64,
    pub change: Vec<ChangeOutput>,
    pub block: Id,
    pub height: u64,
    pub confirmations: u32,
    pub history_anchor: Id,
}
impl NativeFacts {
    pub fn signing_bytes(&self) -> Result<[u8; 64], LedgerError> {
        Ok(codec::signing(
            b"KERB_NATIVE_OBSERVER_V2",
            &codec::native_facts_bytes(self)?,
        ))
    }
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SignedNativeFacts {
    pub facts: NativeFacts,
    pub signature: [u8; 64],
}
#[derive(Clone, Debug, Eq, PartialEq)]
#[expect(
    clippy::large_enum_variant,
    reason = "Owned journal commands retain exact signed facts without per-command heap indirection."
)]
pub enum LedgerCommand {
    IssueCredit {
        claim: FundingClaim,
        source: SignedSourceFacts,
        inventory: SignedInventoryFacts,
    },
    RegisterSponsor {
        inventory: SignedInventoryFacts,
    },
    PrepareHold {
        credit: Id,
        amount: u64,
        refund_receiver: [u8; 43],
        target: TargetHoldBinding,
        authorization: [u8; 64],
    },
    ObserveEpoch {
        target: SignedTargetFacts,
    },
    PrepareAllocation(AllocationPlan),
    RecordAllocationChunk {
        hold: Id,
        allocation: Id,
        index: u32,
        digest: Id,
        target: SignedTargetFacts,
    },
    ActivateAllocation {
        target: SignedTargetFacts,
    },
    PrepareFirstLeg {
        hold: Id,
        portion: Id,
    },
    ObserveSplRelease {
        hold: Id,
        portion: Id,
        recipient: Id,
        target_base_amount: u64,
        target: SignedTargetFacts,
    },
    CancelFirstLeg {
        hold: Id,
        portion: Id,
        target: SignedTargetFacts,
    },
    ReserveInputs {
        inputs: Vec<Id>,
        scope: Id,
    },
    PrepareNative(NativePlan),
    NativeUnknown {
        intent: Id,
        transaction: Id,
    },
    ObserveNative(SignedNativeFacts),
    ImpairInventory {
        inventory: SignedInventoryFacts,
    },
    AuthorizeTarget(TargetAuthorization),
    ObserveTarget(SignedTargetFacts),
}
impl LedgerCommand {
    /// Authorization is excluded from the command's effects digest to avoid a signature cycle.
    pub fn effects_digest(&self) -> Result<Id, LedgerError> {
        Ok(codec::hash(&codec::command_bytes(self, false)?))
    }
    /// Portable NativeIntent effects bind the money decision. The private journal
    /// separately signs the full immutable PCZT/inputs/change/fee/nonce plan.
    pub fn operation_effects(&self, operation: &Operation) -> Result<Id, LedgerError> {
        match self {
            Self::PrepareNative(plan) => ziquid_protocol::market::NativeIntent {
                operation: *operation,
                kind: plan.kind,
                recipient: plan.recipient,
                amount: plan.amount,
                inventory_scope: plan.inventory_scope,
            }
            .effects_digest()
            .map_err(|_| LedgerError::Protocol),
            _ => self.effects_digest(),
        }
    }
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct JournalDecision {
    pub operation: Operation,
    pub command: LedgerCommand,
    pub predecessor: Id,
    pub next_head: Id,
    pub sequence: u64,
    pub target: Option<Decision>,
}
impl JournalDecision {
    pub fn canonical_bytes(&self) -> Result<Vec<u8>, LedgerError> {
        codec::journal_bytes(self)
    }
    pub fn decode(bytes: &[u8]) -> Result<Self, LedgerError> {
        codec::journal_decode(bytes)
    }
    pub fn signing_bytes(&self) -> Result<[u8; 64], LedgerError> {
        Ok(codec::signing(
            b"KERB_PRIVATE_JOURNAL_ACK_V2",
            &self.canonical_bytes()?,
        ))
    }
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct JournalAcknowledgement {
    pub signer: Id,
    pub signature: [u8; 64],
    pub decision: JournalDecision,
    pub target: Option<ziquid_protocol::market::Acknowledgement>,
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RecoveryChallenge {
    pub pair: Id,
    pub nonce: Id,
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RetainedHead {
    pub domain: Domain,
    pub pair: Id,
    pub signer: Id,
    pub head: Id,
    pub target_head: Id,
    pub sequence: u64,
    pub generation: u64,
    pub challenge: Id,
    pub signature: [u8; 64],
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RecoveryState {
    Current,
    PendingRetained,
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PairSnapshot {
    pub available_credit: u128,
    pub prepared: u128,
    pub encumbered: u128,
    pub seller_outstanding: u128,
    pub buyer_unused_outstanding: u128,
    pub final_payout: u128,
    pub final_refund: u128,
    pub usable_inventory: u128,
    pub locked_inventory: u128,
    pub provisional_change: u128,
    pub pending_recipient: u128,
    pub sponsor_inventory: u128,
    pub impaired: bool,
    pub head: Id,
    pub target_head: Id,
    pub sequence: u64,
    pub writer_generation: u64,
    pub target_generation: u64,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct InventoryInput {
    pub note: Id,
    pub occurrence: SourceOccurrence,
    pub note_commitment: Id,
    pub nullifier: Id,
    pub value: u64,
    pub scope: Id,
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CreditState {
    pub credit: Id,
    pub claimant: Id,
    pub amount: u64,
    pub available: u64,
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct HoldState {
    pub hold: Id,
    pub amount: u64,
    pub version: u64,
    pub disposition: ziquid_protocol::market::Disposition,
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct IntentState {
    pub intent: Id,
    pub transaction: Id,
    pub state: IntentStatus,
    pub nonce: Id,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum IntentStatus {
    Prepared,
    Unknown,
    InputConsumed,
    Finalized,
    Disputed,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum LedgerError {
    Database,
    Protocol,
    InvalidPolicy,
    InvalidEvidence,
    InvalidAuthorization,
    Conflict,
    StaleWriter,
    VersionConflict,
    InsufficientCredit,
    DuplicateOccurrence,
    NotReturnable,
    IncompleteAllocation,
    CompetingIntent,
    InventoryUnavailable,
    InventoryImpaired,
    HeadMismatch,
    MissingUnanimity,
    RecoveryEvidenceMissing,
    RollbackDetected,
    SerializationFailure,
    MissingEntity,
}
impl std::fmt::Display for LedgerError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{self:?}")
    }
}
impl std::error::Error for LedgerError {}
