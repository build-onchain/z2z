use super::*;
use ziquid_protocol::market::{
    AllocationKind, ChainCommitment, DECISION_LEN, DOMAIN_LEN, NativeIntentKind, OPERATION_LEN,
};
use sha2::{Digest, Sha256};

pub(crate) const MAX_ITEMS: usize = 4096;
pub const MAX_JOURNAL_BYTES: usize = 1_048_576;

pub(crate) fn hash(bytes: &[u8]) -> Id {
    Sha256::digest(bytes).into()
}
pub(crate) fn signing(role: &[u8], bytes: &[u8]) -> [u8; 64] {
    let mut message = [0; 64];
    message[..32].copy_from_slice(&hash(role));
    message[32..].copy_from_slice(&hash(bytes));
    message
}
pub(crate) struct Encoder(pub Vec<u8>);
impl Encoder {
    pub fn new(tag: &[u8]) -> Self {
        Self(tag.to_vec())
    }
    pub fn raw(&mut self, bytes: &[u8]) {
        self.0.extend_from_slice(bytes);
    }
    pub fn byte(&mut self, value: u8) {
        self.0.push(value);
    }
    pub fn u32(&mut self, value: u32) {
        self.raw(&value.to_le_bytes());
    }
    pub fn u64(&mut self, value: u64) {
        self.raw(&value.to_le_bytes());
    }
    pub fn len(&mut self, value: usize) -> Result<(), LedgerError> {
        if value > MAX_ITEMS {
            return Err(LedgerError::InvalidEvidence);
        }
        self.u32(value as u32);
        Ok(())
    }
    pub fn blob(&mut self, value: &[u8]) -> Result<(), LedgerError> {
        if value.len() > MAX_JOURNAL_BYTES {
            return Err(LedgerError::InvalidEvidence);
        }
        self.u32(value.len() as u32);
        self.raw(value);
        Ok(())
    }
    pub fn domain(&mut self, value: &Domain) -> Result<(), LedgerError> {
        let mut b = [0; DOMAIN_LEN];
        value
            .encode_into(&mut b)
            .map_err(|_| LedgerError::Protocol)?;
        self.raw(&b);
        Ok(())
    }
    pub fn operation(&mut self, value: &Operation) -> Result<(), LedgerError> {
        let mut b = [0; OPERATION_LEN];
        value
            .encode_into(&mut b)
            .map_err(|_| LedgerError::Protocol)?;
        self.raw(&b);
        Ok(())
    }
    pub fn decision(&mut self, value: &Decision) -> Result<(), LedgerError> {
        let mut b = [0; DECISION_LEN];
        value
            .encode_into(&mut b)
            .map_err(|_| LedgerError::Protocol)?;
        self.raw(&b);
        Ok(())
    }
}
pub(crate) struct Decoder<'a> {
    bytes: &'a [u8],
    offset: usize,
}
impl<'a> Decoder<'a> {
    pub fn new(bytes: &'a [u8], tag: &[u8]) -> Result<Self, LedgerError> {
        if bytes.len() > MAX_JOURNAL_BYTES || !bytes.starts_with(tag) {
            return Err(LedgerError::InvalidEvidence);
        }
        Ok(Self {
            bytes,
            offset: tag.len(),
        })
    }
    pub fn bytes(&mut self, count: usize) -> Result<&'a [u8], LedgerError> {
        let end = self
            .offset
            .checked_add(count)
            .ok_or(LedgerError::InvalidEvidence)?;
        let b = self
            .bytes
            .get(self.offset..end)
            .ok_or(LedgerError::InvalidEvidence)?;
        self.offset = end;
        Ok(b)
    }
    pub fn array<const N: usize>(&mut self) -> Result<[u8; N], LedgerError> {
        self.bytes(N)?
            .try_into()
            .map_err(|_| LedgerError::InvalidEvidence)
    }
    pub fn byte(&mut self) -> Result<u8, LedgerError> {
        Ok(self.array::<1>()?[0])
    }
    pub fn u32(&mut self) -> Result<u32, LedgerError> {
        Ok(u32::from_le_bytes(self.array()?))
    }
    pub fn u64(&mut self) -> Result<u64, LedgerError> {
        Ok(u64::from_le_bytes(self.array()?))
    }
    pub fn len(&mut self) -> Result<usize, LedgerError> {
        let len = self.u32()? as usize;
        if len > MAX_ITEMS {
            Err(LedgerError::InvalidEvidence)
        } else {
            Ok(len)
        }
    }
    pub fn blob(&mut self) -> Result<&'a [u8], LedgerError> {
        let len = self.u32()? as usize;
        self.bytes(len)
    }
    pub fn end(self) -> Result<(), LedgerError> {
        if self.offset == self.bytes.len() {
            Ok(())
        } else {
            Err(LedgerError::InvalidEvidence)
        }
    }
    pub fn domain(&mut self) -> Result<Domain, LedgerError> {
        Domain::decode(self.bytes(DOMAIN_LEN)?).map_err(|_| LedgerError::Protocol)
    }
    pub fn operation(&mut self) -> Result<Operation, LedgerError> {
        Operation::decode(self.bytes(OPERATION_LEN)?).map_err(|_| LedgerError::Protocol)
    }
    pub fn decision(&mut self) -> Result<Decision, LedgerError> {
        Decision::decode(self.bytes(DECISION_LEN)?).map_err(|_| LedgerError::Protocol)
    }
}
fn environment(d: &mut Decoder<'_>) -> Result<ObservationEnvironment, LedgerError> {
    match d.byte()? {
        1 => Ok(ObservationEnvironment::LocalFixture),
        2 => Ok(ObservationEnvironment::Network),
        _ => Err(LedgerError::InvalidEvidence),
    }
}
fn occurrence(e: &mut Encoder, v: &SourceOccurrence) {
    e.byte(v.network);
    e.byte(v.pool);
    e.raw(&v.txid);
    e.u32(v.action_index);
}
fn read_occurrence(d: &mut Decoder<'_>) -> Result<SourceOccurrence, LedgerError> {
    Ok(SourceOccurrence {
        network: d.byte()?,
        pool: d.byte()?,
        txid: d.array()?,
        action_index: d.u32()?,
    })
}
fn source(e: &mut Encoder, v: &SourceFacts) -> Result<(), LedgerError> {
    e.domain(&v.domain)?;
    e.byte(v.provenance as u8);
    occurrence(e, &v.occurrence);
    e.raw(&v.receiver);
    e.u64(v.value);
    e.raw(&v.block);
    e.u64(v.height);
    e.u32(v.confirmations);
    e.raw(&v.history_anchor);
    e.raw(&v.policy);
    match v.effect {
        SourceEffect::Deposit {
            claimant,
            credit_intent,
        } => {
            e.byte(1);
            e.raw(&claimant);
            e.raw(&credit_intent);
        }
        SourceEffect::Change { parent_intent } => {
            e.byte(2);
            e.raw(&parent_intent);
        }
        SourceEffect::Unclaimed => e.byte(3),
        SourceEffect::HistoryGap => e.byte(4),
        SourceEffect::Reorged => e.byte(5),
        SourceEffect::Unknown => e.byte(6),
    }
    Ok(())
}
fn read_source(d: &mut Decoder<'_>) -> Result<SourceFacts, LedgerError> {
    let domain = d.domain()?;
    let provenance = environment(d)?;
    let occurrence = read_occurrence(d)?;
    let receiver = d.array()?;
    let value = d.u64()?;
    let block = d.array()?;
    let height = d.u64()?;
    let confirmations = d.u32()?;
    let history_anchor = d.array()?;
    let policy = d.array()?;
    let effect = match d.byte()? {
        1 => SourceEffect::Deposit {
            claimant: d.array()?,
            credit_intent: d.array()?,
        },
        2 => SourceEffect::Change {
            parent_intent: d.array()?,
        },
        3 => SourceEffect::Unclaimed,
        4 => SourceEffect::HistoryGap,
        5 => SourceEffect::Reorged,
        6 => SourceEffect::Unknown,
        _ => return Err(LedgerError::InvalidEvidence),
    };
    Ok(SourceFacts {
        domain,
        provenance,
        occurrence,
        receiver,
        value,
        block,
        height,
        confirmations,
        history_anchor,
        policy,
        effect,
    })
}
fn inventory(e: &mut Encoder, v: &InventoryFacts) -> Result<(), LedgerError> {
    e.domain(&v.domain)?;
    e.byte(v.provenance as u8);
    e.raw(&v.note);
    occurrence(e, &v.occurrence);
    e.raw(&v.note_commitment);
    e.raw(&v.nullifier);
    e.raw(&v.receiver);
    e.u64(v.value);
    e.raw(&v.scope);
    e.raw(&v.control);
    match v.origin {
        InventoryOrigin::Deposit => e.byte(1),
        InventoryOrigin::Change { parent_intent } => {
            e.byte(2);
            e.raw(&parent_intent);
        }
        InventoryOrigin::Sponsor => e.byte(3),
    }
    e.byte(match v.condition {
        InventoryCondition::Spendable => 1,
        InventoryCondition::HistoryGap => 2,
        InventoryCondition::Reorged => 3,
        InventoryCondition::Unknown => 4,
    });
    e.raw(&v.history_anchor);
    Ok(())
}
fn read_inventory(d: &mut Decoder<'_>) -> Result<InventoryFacts, LedgerError> {
    let domain = d.domain()?;
    let provenance = environment(d)?;
    let note = d.array()?;
    let occurrence = read_occurrence(d)?;
    let note_commitment = d.array()?;
    let nullifier = d.array()?;
    let receiver = d.array()?;
    let value = d.u64()?;
    let scope = d.array()?;
    let control = d.array()?;
    let origin = match d.byte()? {
        1 => InventoryOrigin::Deposit,
        2 => InventoryOrigin::Change {
            parent_intent: d.array()?,
        },
        3 => InventoryOrigin::Sponsor,
        _ => return Err(LedgerError::InvalidEvidence),
    };
    let condition = match d.byte()? {
        1 => InventoryCondition::Spendable,
        2 => InventoryCondition::HistoryGap,
        3 => InventoryCondition::Reorged,
        4 => InventoryCondition::Unknown,
        _ => return Err(LedgerError::InvalidEvidence),
    };
    Ok(InventoryFacts {
        domain,
        provenance,
        note,
        occurrence,
        note_commitment,
        nullifier,
        receiver,
        value,
        scope,
        control,
        origin,
        condition,
        history_anchor: d.array()?,
    })
}
fn target(e: &mut Encoder, v: &TargetFacts) -> Result<(), LedgerError> {
    e.decision(&v.decision)?;
    let o = v.observation;
    e.byte(o.environment as u8);
    e.raw(&o.operation);
    e.raw(&o.transaction);
    e.u64(o.slot);
    e.byte(o.commitment as u8);
    e.raw(&o.effects);
    Ok(())
}
fn read_target(d: &mut Decoder<'_>) -> Result<TargetFacts, LedgerError> {
    let decision = d.decision()?;
    let environment = environment(d)?;
    let operation = d.array()?;
    let transaction = d.array()?;
    let slot = d.u64()?;
    let commitment = match d.byte()? {
        1 => ChainCommitment::Submitted,
        2 => ChainCommitment::Confirmed,
        3 => ChainCommitment::Finalized,
        _ => return Err(LedgerError::InvalidEvidence),
    };
    Ok(TargetFacts {
        decision,
        observation: ChainObservation {
            environment,
            operation,
            transaction,
            slot,
            commitment,
            effects: d.array()?,
        },
    })
}
fn signed_target(e: &mut Encoder, v: &SignedTargetFacts) -> Result<(), LedgerError> {
    target(e, &v.facts)?;
    e.raw(&v.signature);
    Ok(())
}
fn read_signed_target(d: &mut Decoder<'_>) -> Result<SignedTargetFacts, LedgerError> {
    Ok(SignedTargetFacts {
        facts: read_target(d)?,
        signature: d.array()?,
    })
}
fn target_evidence(e: &mut Encoder, v: &TargetHoldEvidence) -> Result<(), LedgerError> {
    match v {
        TargetHoldEvidence::Prepared { prepare } => {
            e.byte(1);
            signed_target(e, prepare)?;
        }
        TargetHoldEvidence::Locked {
            anchor,
            lock_transaction,
            lock_slot,
        } => {
            e.byte(2);
            signed_target(e, anchor)?;
            e.raw(lock_transaction);
            e.u64(*lock_slot);
        }
    }
    Ok(())
}
fn read_target_evidence(d: &mut Decoder<'_>) -> Result<TargetHoldEvidence, LedgerError> {
    match d.byte()? {
        1 => Ok(TargetHoldEvidence::Prepared {
            prepare: read_signed_target(d)?,
        }),
        2 => Ok(TargetHoldEvidence::Locked {
            anchor: read_signed_target(d)?,
            lock_transaction: d.array()?,
            lock_slot: d.u64()?,
        }),
        _ => Err(LedgerError::InvalidEvidence),
    }
}
fn target_binding(e: &mut Encoder, v: &TargetHoldBinding) -> Result<(), LedgerError> {
    e.domain(&v.domain)?;
    e.raw(&v.hold_business);
    e.u64(v.maximum_base);
    e.u32(v.expected_chunks);
    e.raw(&v.refund_token);
    e.u64(v.epoch_version);
    target_evidence(e, &v.evidence)?;
    e.raw(&v.signature);
    Ok(())
}
fn read_target_binding(d: &mut Decoder<'_>) -> Result<TargetHoldBinding, LedgerError> {
    Ok(TargetHoldBinding {
        domain: d.domain()?,
        hold_business: d.array()?,
        maximum_base: d.u64()?,
        expected_chunks: d.u32()?,
        refund_token: d.array()?,
        epoch_version: d.u64()?,
        evidence: read_target_evidence(d)?,
        signature: d.array()?,
    })
}
pub(crate) fn target_binding_bytes(v: &TargetHoldBinding) -> Result<Vec<u8>, LedgerError> {
    let mut e = Encoder::new(b"KERBTB01");
    e.domain(&v.domain)?;
    e.raw(&v.hold_business);
    e.u64(v.maximum_base);
    e.u32(v.expected_chunks);
    e.raw(&v.refund_token);
    e.u64(v.epoch_version);
    target_evidence(&mut e, &v.evidence)?;
    Ok(e.0)
}
pub(crate) fn target_binding_stored(v: &TargetHoldBinding) -> Result<Vec<u8>, LedgerError> {
    let mut e = Encoder::new(b"KERBTS01");
    target_binding(&mut e, v)?;
    Ok(e.0)
}
pub(crate) fn target_binding_decode(bytes: &[u8]) -> Result<TargetHoldBinding, LedgerError> {
    let mut d = Decoder::new(bytes, b"KERBTS01")?;
    let binding = read_target_binding(&mut d)?;
    d.end()?;
    Ok(binding)
}
fn claim(e: &mut Encoder, v: &FundingClaim) -> Result<(), LedgerError> {
    e.domain(&v.domain)?;
    occurrence(e, &v.occurrence);
    e.raw(&v.claimant);
    e.raw(&v.receiver);
    e.u64(v.value);
    e.raw(&v.block_policy);
    e.raw(&v.inventory_note);
    e.raw(&v.evidence_digest);
    e.raw(&v.credit_intent);
    e.raw(&v.authorization);
    Ok(())
}
fn read_claim(d: &mut Decoder<'_>) -> Result<FundingClaim, LedgerError> {
    Ok(FundingClaim {
        domain: d.domain()?,
        occurrence: read_occurrence(d)?,
        claimant: d.array()?,
        receiver: d.array()?,
        value: d.u64()?,
        block_policy: d.array()?,
        inventory_note: d.array()?,
        evidence_digest: d.array()?,
        credit_intent: d.array()?,
        authorization: d.array()?,
    })
}
fn changes(e: &mut Encoder, v: &[ChangeOutput]) -> Result<(), LedgerError> {
    e.len(v.len())?;
    for c in v {
        e.raw(&c.note);
        e.u32(c.action_index);
        e.raw(&c.note_commitment);
        e.raw(&c.nullifier);
        e.raw(&c.receiver);
        e.u64(c.value);
    }
    Ok(())
}
fn read_changes(d: &mut Decoder<'_>) -> Result<Vec<ChangeOutput>, LedgerError> {
    let len = d.len()?;
    (0..len)
        .map(|_| {
            Ok(ChangeOutput {
                note: d.array()?,
                action_index: d.u32()?,
                note_commitment: d.array()?,
                nullifier: d.array()?,
                receiver: d.array()?,
                value: d.u64()?,
            })
        })
        .collect()
}
fn ids(e: &mut Encoder, v: &[Id]) -> Result<(), LedgerError> {
    e.len(v.len())?;
    for id in v {
        e.raw(id);
    }
    Ok(())
}
fn read_ids(d: &mut Decoder<'_>) -> Result<Vec<Id>, LedgerError> {
    let len = d.len()?;
    (0..len).map(|_| d.array()).collect()
}
fn native_kind(d: &mut Decoder<'_>) -> Result<NativeIntentKind, LedgerError> {
    match d.byte()? {
        1 => Ok(NativeIntentKind::SellerPayout),
        2 => Ok(NativeIntentKind::BuyerRefund),
        3 => Ok(NativeIntentKind::SponsorFee),
        _ => Err(LedgerError::InvalidEvidence),
    }
}
pub(crate) fn allocation_bytes(v: &AllocationPlan) -> Result<Vec<u8>, LedgerError> {
    let mut e = Encoder::new(b"KERBAP01");
    allocation(&mut e, v)?;
    Ok(e.0)
}
fn allocation(e: &mut Encoder, v: &AllocationPlan) -> Result<(), LedgerError> {
    e.raw(&v.hold);
    e.raw(&v.allocation);
    e.len(v.portions.len())?;
    for p in &v.portions {
        e.raw(&p.portion);
        e.u64(p.offset);
        e.u64(p.amount);
        e.byte(p.kind as u8);
        e.raw(&p.native_recipient);
        e.raw(&p.spl_recipient);
        e.u64(p.target_base_offset);
        e.u64(p.target_base_amount);
        e.raw(&p.fill_fence);
    }
    ids(e, &v.chunks)
}
fn read_allocation(d: &mut Decoder<'_>) -> Result<AllocationPlan, LedgerError> {
    let hold = d.array()?;
    let allocation = d.array()?;
    let len = d.len()?;
    let mut portions = Vec::with_capacity(len);
    for _ in 0..len {
        portions.push(PortionSpec {
            portion: d.array()?,
            offset: d.u64()?,
            amount: d.u64()?,
            kind: match d.byte()? {
                1 => AllocationKind::SellerLiability,
                2 => AllocationKind::BuyerUnused,
                _ => return Err(LedgerError::InvalidEvidence),
            },
            native_recipient: d.array()?,
            spl_recipient: d.array()?,
            target_base_offset: d.u64()?,
            target_base_amount: d.u64()?,
            fill_fence: d.array()?,
        });
    }
    Ok(AllocationPlan {
        hold,
        allocation,
        portions,
        chunks: read_ids(d)?,
    })
}
pub(crate) fn native_plan_bytes(v: &NativePlan) -> Result<Vec<u8>, LedgerError> {
    let mut e = Encoder::new(b"KERBNP02");
    native_plan(&mut e, v)?;
    Ok(e.0)
}
pub(crate) fn decode_native_plan(bytes: &[u8]) -> Result<NativePlan, LedgerError> {
    let mut d = Decoder::new(bytes, b"KERBNP02")?;
    let v = read_native_plan(&mut d)?;
    d.end()?;
    Ok(v)
}
fn native_plan(e: &mut Encoder, v: &NativePlan) -> Result<(), LedgerError> {
    e.raw(&v.hold);
    e.raw(&v.portion);
    e.byte(v.kind as u8);
    e.raw(&v.recipient);
    e.u64(v.amount);
    e.raw(&v.inventory_scope);
    ids(e, &v.inputs)?;
    ids(e, &v.fee_inputs)?;
    changes(e, &v.change)?;
    e.u64(v.fee);
    e.raw(&v.nonce);
    e.raw(&v.pczt_digest);
    e.raw(&v.sighash);
    e.raw(&v.transaction);
    Ok(())
}
fn read_native_plan(d: &mut Decoder<'_>) -> Result<NativePlan, LedgerError> {
    Ok(NativePlan {
        hold: d.array()?,
        portion: d.array()?,
        kind: native_kind(d)?,
        recipient: d.array()?,
        amount: d.u64()?,
        inventory_scope: d.array()?,
        inputs: read_ids(d)?,
        fee_inputs: read_ids(d)?,
        change: read_changes(d)?,
        fee: d.u64()?,
        nonce: d.array()?,
        pczt_digest: d.array()?,
        sighash: d.array()?,
        transaction: d.array()?,
    })
}
fn native_facts(e: &mut Encoder, v: &NativeFacts) -> Result<(), LedgerError> {
    e.domain(&v.domain)?;
    e.byte(v.provenance as u8);
    e.raw(&v.intent);
    e.raw(&v.transaction);
    ids(e, &v.inputs)?;
    e.raw(&v.recipient);
    e.u64(v.amount);
    changes(e, &v.change)?;
    e.raw(&v.block);
    e.u64(v.height);
    e.u32(v.confirmations);
    e.raw(&v.history_anchor);
    Ok(())
}
fn read_native_facts(d: &mut Decoder<'_>) -> Result<NativeFacts, LedgerError> {
    Ok(NativeFacts {
        domain: d.domain()?,
        provenance: environment(d)?,
        intent: d.array()?,
        transaction: d.array()?,
        inputs: read_ids(d)?,
        recipient: d.array()?,
        amount: d.u64()?,
        change: read_changes(d)?,
        block: d.array()?,
        height: d.u64()?,
        confirmations: d.u32()?,
        history_anchor: d.array()?,
    })
}
pub(crate) fn inventory_bytes(v: &InventoryFacts) -> Result<Vec<u8>, LedgerError> {
    let mut e = Encoder::new(b"KERBIF02");
    inventory(&mut e, v)?;
    Ok(e.0)
}
pub(crate) fn native_facts_bytes(v: &NativeFacts) -> Result<Vec<u8>, LedgerError> {
    let mut e = Encoder::new(b"KERBNF02");
    native_facts(&mut e, v)?;
    Ok(e.0)
}
pub(crate) fn source_bytes(v: &SourceFacts) -> Result<Vec<u8>, LedgerError> {
    let mut e = Encoder::new(b"KERBSF01");
    source(&mut e, v)?;
    Ok(e.0)
}
pub(crate) fn target_bytes(v: &TargetFacts) -> Result<Vec<u8>, LedgerError> {
    let mut e = Encoder::new(b"KERBTF01");
    target(&mut e, v)?;
    Ok(e.0)
}
pub(crate) fn command_bytes(
    command: &LedgerCommand,
    include_authorization: bool,
) -> Result<Vec<u8>, LedgerError> {
    let mut e = Encoder::new(b"KERBCM02");
    match command {
        LedgerCommand::IssueCredit {
            claim: c,
            source: s,
            inventory: i,
        } => {
            e.byte(1);
            claim(&mut e, c)?;
            source(&mut e, &s.facts)?;
            e.raw(&s.signature);
            inventory(&mut e, &i.facts)?;
            e.raw(&i.signature);
        }
        LedgerCommand::RegisterSponsor { inventory: i } => {
            e.byte(2);
            inventory(&mut e, &i.facts)?;
            e.raw(&i.signature);
        }
        LedgerCommand::PrepareHold {
            credit,
            amount,
            refund_receiver,
            target,
            authorization,
        } => {
            e.byte(3);
            e.raw(credit);
            e.u64(*amount);
            e.raw(refund_receiver);
            target_binding(&mut e, target)?;
            if include_authorization {
                e.raw(authorization);
            }
        }
        LedgerCommand::ObserveEpoch { target: t } => {
            e.byte(4);
            signed_target(&mut e, t)?;
        }
        LedgerCommand::PrepareAllocation(v) => {
            e.byte(5);
            allocation(&mut e, v)?;
        }
        LedgerCommand::RecordAllocationChunk {
            hold,
            allocation,
            index,
            digest,
            target: t,
        } => {
            e.byte(6);
            e.raw(hold);
            e.raw(allocation);
            e.u32(*index);
            e.raw(digest);
            signed_target(&mut e, t)?;
        }
        LedgerCommand::ActivateAllocation { target: t } => {
            e.byte(7);
            signed_target(&mut e, t)?;
        }
        LedgerCommand::PrepareFirstLeg { hold, portion } => {
            e.byte(8);
            e.raw(hold);
            e.raw(portion);
        }
        LedgerCommand::ObserveSplRelease {
            hold,
            portion,
            recipient,
            target_base_amount,
            target: t,
        } => {
            e.byte(9);
            e.raw(hold);
            e.raw(portion);
            e.raw(recipient);
            e.u64(*target_base_amount);
            signed_target(&mut e, t)?;
        }
        LedgerCommand::CancelFirstLeg {
            hold,
            portion,
            target: t,
        } => {
            e.byte(10);
            e.raw(hold);
            e.raw(portion);
            signed_target(&mut e, t)?;
        }
        LedgerCommand::ReserveInputs { inputs, scope } => {
            e.byte(11);
            ids(&mut e, inputs)?;
            e.raw(scope);
        }
        LedgerCommand::PrepareNative(v) => {
            e.byte(12);
            native_plan(&mut e, v)?;
        }
        LedgerCommand::NativeUnknown {
            intent,
            transaction,
        } => {
            e.byte(13);
            e.raw(intent);
            e.raw(transaction);
        }
        LedgerCommand::ObserveNative(v) => {
            e.byte(14);
            native_facts(&mut e, &v.facts)?;
            e.raw(&v.signature);
        }
        LedgerCommand::ImpairInventory { inventory: i } => {
            e.byte(15);
            inventory(&mut e, &i.facts)?;
            e.raw(&i.signature);
        }
        LedgerCommand::AuthorizeTarget(v) => {
            e.byte(16);
            e.raw(&v.hold);
            e.raw(&v.portion);
            e.decision(&v.decision)?;
            e.blob(&v.payload)?;
            ids(&mut e, &v.accounts)?;
        }
        LedgerCommand::ObserveTarget(v) => {
            e.byte(17);
            signed_target(&mut e, v)?;
        }
    }
    if e.0.len() > MAX_JOURNAL_BYTES {
        Err(LedgerError::InvalidEvidence)
    } else {
        Ok(e.0)
    }
}
pub(crate) fn read_command(bytes: &[u8]) -> Result<LedgerCommand, LedgerError> {
    let mut d = Decoder::new(bytes, b"KERBCM02")?;
    let v = match d.byte()? {
        1 => LedgerCommand::IssueCredit {
            claim: read_claim(&mut d)?,
            source: SignedSourceFacts {
                facts: read_source(&mut d)?,
                signature: d.array()?,
            },
            inventory: SignedInventoryFacts {
                facts: read_inventory(&mut d)?,
                signature: d.array()?,
            },
        },
        2 => LedgerCommand::RegisterSponsor {
            inventory: SignedInventoryFacts {
                facts: read_inventory(&mut d)?,
                signature: d.array()?,
            },
        },
        3 => LedgerCommand::PrepareHold {
            credit: d.array()?,
            amount: d.u64()?,
            refund_receiver: d.array()?,
            target: read_target_binding(&mut d)?,
            authorization: d.array()?,
        },
        4 => LedgerCommand::ObserveEpoch {
            target: read_signed_target(&mut d)?,
        },
        5 => LedgerCommand::PrepareAllocation(read_allocation(&mut d)?),
        6 => LedgerCommand::RecordAllocationChunk {
            hold: d.array()?,
            allocation: d.array()?,
            index: d.u32()?,
            digest: d.array()?,
            target: read_signed_target(&mut d)?,
        },
        7 => LedgerCommand::ActivateAllocation {
            target: read_signed_target(&mut d)?,
        },
        8 => LedgerCommand::PrepareFirstLeg {
            hold: d.array()?,
            portion: d.array()?,
        },
        9 => LedgerCommand::ObserveSplRelease {
            hold: d.array()?,
            portion: d.array()?,
            recipient: d.array()?,
            target_base_amount: d.u64()?,
            target: read_signed_target(&mut d)?,
        },
        10 => LedgerCommand::CancelFirstLeg {
            hold: d.array()?,
            portion: d.array()?,
            target: read_signed_target(&mut d)?,
        },
        11 => LedgerCommand::ReserveInputs {
            inputs: read_ids(&mut d)?,
            scope: d.array()?,
        },
        12 => LedgerCommand::PrepareNative(read_native_plan(&mut d)?),
        13 => LedgerCommand::NativeUnknown {
            intent: d.array()?,
            transaction: d.array()?,
        },
        14 => LedgerCommand::ObserveNative(SignedNativeFacts {
            facts: read_native_facts(&mut d)?,
            signature: d.array()?,
        }),
        15 => LedgerCommand::ImpairInventory {
            inventory: SignedInventoryFacts {
                facts: read_inventory(&mut d)?,
                signature: d.array()?,
            },
        },
        16 => LedgerCommand::AuthorizeTarget(TargetAuthorization {
            hold: d.array()?,
            portion: d.array()?,
            decision: d.decision()?,
            payload: d.blob()?.to_vec(),
            accounts: read_ids(&mut d)?,
        }),
        17 => LedgerCommand::ObserveTarget(read_signed_target(&mut d)?),
        _ => return Err(LedgerError::InvalidEvidence),
    };
    d.end()?;
    Ok(v)
}
pub(crate) fn command_target(command: &LedgerCommand) -> Option<&SignedTargetFacts> {
    match command {
        LedgerCommand::ObserveEpoch { target, .. }
        | LedgerCommand::RecordAllocationChunk { target, .. }
        | LedgerCommand::ActivateAllocation { target, .. }
        | LedgerCommand::ObserveSplRelease { target, .. }
        | LedgerCommand::CancelFirstLeg { target, .. }
        | LedgerCommand::ObserveTarget(target) => Some(target),
        _ => None,
    }
}
pub(crate) fn command_signing_target(command: &LedgerCommand) -> Option<Decision> {
    match command {
        LedgerCommand::AuthorizeTarget(v) => Some(v.decision),
        _ => None,
    }
}
pub(crate) fn journal_body(v: &JournalDecision) -> Result<Vec<u8>, LedgerError> {
    let mut e = Encoder::new(b"KERBJH02");
    e.operation(&v.operation)?;
    e.raw(&v.predecessor);
    e.u64(v.sequence);
    e.blob(&command_bytes(&v.command, true)?)?;
    match v.target {
        Some(target) => {
            e.byte(1);
            e.decision(&target)?;
        }
        None => e.byte(0),
    }
    Ok(e.0)
}
pub(crate) fn journal_bytes(v: &JournalDecision) -> Result<Vec<u8>, LedgerError> {
    validate_journal(v)?;
    let mut b = journal_body(v)?;
    b.extend_from_slice(&v.next_head);
    if b.len() > MAX_JOURNAL_BYTES {
        Err(LedgerError::InvalidEvidence)
    } else {
        Ok(b)
    }
}
pub(crate) fn journal_decode(bytes: &[u8]) -> Result<JournalDecision, LedgerError> {
    let mut d = Decoder::new(bytes, b"KERBJH02")?;
    let operation = d.operation()?;
    let predecessor = d.array()?;
    let sequence = d.u64()?;
    let command = read_command(d.blob()?)?;
    let target = match d.byte()? {
        0 => None,
        1 => Some(d.decision()?),
        _ => return Err(LedgerError::InvalidEvidence),
    };
    let v = JournalDecision {
        operation,
        command,
        predecessor,
        next_head: d.array()?,
        sequence,
        target,
    };
    d.end()?;
    validate_journal(&v)?;
    Ok(v)
}
pub(crate) fn validate_journal(v: &JournalDecision) -> Result<(), LedgerError> {
    v.operation.validate().map_err(|_| LedgerError::Protocol)?;
    if v.sequence == 0
        || v.operation.effects != v.command.operation_effects(&v.operation)?
        || v.target != command_signing_target(&v.command)
        || hash(&journal_body(v)?) != v.next_head
    {
        return Err(LedgerError::Conflict);
    }
    Ok(())
}
pub(crate) fn policy_bytes(v: &PairPolicy) -> Result<Vec<u8>, LedgerError> {
    let mut e = Encoder::new(b"KERBPP01");
    e.domain(&v.domain)?;
    e.byte(v.environment as u8);
    e.raw(&v.source_policy);
    e.raw(&v.history_anchor);
    e.u32(v.minimum_confirmations);
    e.raw(&v.receiver);
    e.raw(&v.inventory_scope);
    e.raw(&v.sponsor_scope);
    e.raw(&v.source_producer);
    e.raw(&v.inventory_producer);
    e.raw(&v.target_observer);
    e.raw(&v.target_admin);
    for key in &v.roster {
        e.raw(key);
    }
    Ok(e.0)
}
pub(crate) fn policy_decode(bytes: &[u8]) -> Result<PairPolicy, LedgerError> {
    let mut d = Decoder::new(bytes, b"KERBPP01")?;
    let v = PairPolicy {
        domain: d.domain()?,
        environment: environment(&mut d)?,
        source_policy: d.array()?,
        history_anchor: d.array()?,
        minimum_confirmations: d.u32()?,
        receiver: d.array()?,
        inventory_scope: d.array()?,
        sponsor_scope: d.array()?,
        source_producer: d.array()?,
        inventory_producer: d.array()?,
        target_observer: d.array()?,
        target_admin: d.array()?,
        roster: [d.array()?, d.array()?, d.array()?],
    };
    d.end()?;
    Ok(v)
}
pub(crate) fn retained_bytes(v: &RetainedHead) -> Result<Vec<u8>, LedgerError> {
    let mut e = Encoder::new(b"KERBRH01");
    e.domain(&v.domain)?;
    e.raw(&v.pair);
    e.raw(&v.signer);
    e.raw(&v.head);
    e.raw(&v.target_head);
    e.u64(v.sequence);
    e.u64(v.generation);
    e.raw(&v.challenge);
    Ok(e.0)
}

#[cfg(test)]
mod tests {
    use super::*;
    use ziquid_protocol::market::{SOURCE_BRANCH_NU6_3, SOURCE_NETWORK_TESTNET, SOURCE_POOL_IRONWOOD, SOURCE_TRANSACTION_VERSION, LEGACY_TOKEN_PROGRAM, Transition};

    fn domain() -> Domain {
        Domain { schema_version:1, deployment:[1;32], solana_genesis:[2;32], solana_program:[3;32], mint:[4;32], token_program:LEGACY_TOKEN_PROGRAM,
            source_network:SOURCE_NETWORK_TESTNET, source_pool:SOURCE_POOL_IRONWOOD, source_branch:SOURCE_BRANCH_NU6_3, source_tx_version:SOURCE_TRANSACTION_VERSION,
            source_genesis:[5;32], receiver_policy:[6;32], pair:[7;32], epoch:1, rules_hash:[8;32], roster_version:1, signature_scheme:1 }
    }

    #[test]
    fn canonical_command_bytes_keep_original_tag_width_and_little_endian_fields() {
        let command = LedgerCommand::PrepareFirstLeg { hold:[0x11;32], portion:[0x22;32] };
        let mut expected = b"KERBCM02\x08".to_vec();
        expected.extend_from_slice(&[0x11;32]);
        expected.extend_from_slice(&[0x22;32]);
        assert_eq!(command.canonical_bytes().unwrap(), expected);
        assert_eq!(LedgerCommand::decode(&expected).unwrap(), command);
        let mut old = expected.clone(); old[..8].copy_from_slice(b"KERBCM01");
        assert_eq!(LedgerCommand::decode(&old), Err(LedgerError::InvalidEvidence));
        expected.push(0);
        assert_eq!(LedgerCommand::decode(&expected), Err(LedgerError::InvalidEvidence));
        let mut encoded = Encoder::new(&[]);
        encoded.u32(0x0403_0201); encoded.u64(0x0c0b_0a09_0807_0605);
        assert_eq!(encoded.0, [1,2,3,4,5,6,7,8,9,10,11,12]);
    }

    #[test]
    fn acknowledgement_and_recovery_frames_reject_old_tags_and_mutated_journal_bodies() {
        let command = LedgerCommand::PrepareFirstLeg { hold:[0x11;32], portion:[0x22;32] };
        let operation = Operation { domain:domain(), entity:[0x11;32], portion:[0x22;32], intent:[0x33;32], generation:1, prior_version:0,
            transition:Transition::PrepareFill, effects:command.effects_digest().unwrap() };
        let mut decision = JournalDecision { operation, command, predecessor:[0;32], next_head:[0;32], sequence:1, target:None };
        decision.next_head = hash(&journal_body(&decision).unwrap());
        let bytes = decision.canonical_bytes().unwrap();
        assert_eq!(JournalDecision::decode(&bytes).unwrap(), decision);
        let mut old = bytes.clone(); old[..8].copy_from_slice(b"KERBJH01");
        assert_eq!(JournalDecision::decode(&old), Err(LedgerError::InvalidEvidence));
        let mut altered = bytes.clone(); *altered.last_mut().unwrap() ^= 1;
        assert_eq!(JournalDecision::decode(&altered), Err(LedgerError::Conflict));
        let ack = JournalAcknowledgement { signer:[0x44;32], signature:[0x55;64], decision, target:None };
        let mut bytes = ack.canonical_bytes().unwrap();
        assert_eq!(JournalAcknowledgement::decode(&bytes).unwrap(), ack);
        bytes[..8].copy_from_slice(b"KERBJA01");
        assert_eq!(JournalAcknowledgement::decode(&bytes), Err(LedgerError::InvalidEvidence));
        let challenge = RecoveryChallenge { pair:[0x66;32], nonce:[0x77;32] };
        let mut expected = [0_u8;72]; expected[..8].copy_from_slice(b"KERBRC01");
        expected[8..40].fill(0x66); expected[40..].fill(0x77);
        assert_eq!(challenge.canonical_bytes(), expected);
        assert_eq!(RecoveryChallenge::decode(&expected).unwrap(), challenge);
    }
}
