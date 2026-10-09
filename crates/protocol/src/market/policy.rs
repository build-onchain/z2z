use super::domain::{check_frame, read_array};
use super::records::{SignatureRole, signing_message};
use super::{
    ACK_SIGNING_LEN, ChainCommitment, ChainObservation, Domain, Id, ObservationEnvironment,
    Operation, ProtocolError, Transition, sha256,
};
use sha2::{Digest, Sha256};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Units {
    pub base_atoms_per_lot: u64,
    pub quote_atoms_per_lot_tick: u64,
}
impl Units {
    pub fn validate(&self) -> Result<(), ProtocolError> {
        if self.base_atoms_per_lot == 0 || self.quote_atoms_per_lot_tick == 0 {
            return Err(ProtocolError::ZeroUnits);
        }
        Ok(())
    }
}

pub fn base_atoms(lots: u64, units: Units) -> Result<u64, ProtocolError> {
    units.validate()?;
    let amount = u128::from(lots)
        .checked_mul(u128::from(units.base_atoms_per_lot))
        .ok_or(ProtocolError::Overflow)?;
    u64::try_from(amount).map_err(|_| ProtocolError::Overflow)
}

pub fn notional(lots: u64, ticks: u64, units: Units) -> Result<u64, ProtocolError> {
    units.validate()?;
    let amount = u128::from(lots)
        .checked_mul(u128::from(ticks))
        .and_then(|product| product.checked_mul(u128::from(units.quote_atoms_per_lot_tick)))
        .ok_or(ProtocolError::Overflow)?;
    u64::try_from(amount).map_err(|_| ProtocolError::Overflow)
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum AllocationKind {
    SellerLiability = 1,
    BuyerUnused = 2,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AllocationPortion {
    pub portion: Id,
    pub offset: u64,
    pub amount: u64,
    pub kind: AllocationKind,
}

/// Disjoint half-open intervals within one previously held maximum debit.
/// Membership, authenticated chunks and activation remain consumer-owned facts.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AllocationPartition<'a> {
    pub portions: &'a [AllocationPortion],
}
impl AllocationPartition<'_> {
    pub fn validate(&self, max_debit: u64) -> Result<(), ProtocolError> {
        let mut total = 0u128;
        // ponytail: pairwise disjointness is O(n²), with no target heap or sorting.
        // Switch to caller-provided sorted intervals if large partitions are needed.
        for (index, portion) in self.portions.iter().enumerate() {
            if portion.amount == 0 {
                return Err(ProtocolError::ZeroAmount);
            }
            if portion.portion == [0; 32] {
                return Err(ProtocolError::EvidenceMismatch);
            }
            let start = u128::from(portion.offset);
            let end = start
                .checked_add(u128::from(portion.amount))
                .ok_or(ProtocolError::Overflow)?;
            if end > u128::from(max_debit) {
                return Err(ProtocolError::PartitionMismatch);
            }
            for previous in &self.portions[..index] {
                if previous.portion == portion.portion {
                    return Err(ProtocolError::DuplicatePortion);
                }
                let previous_end = u128::from(previous.offset)
                    .checked_add(u128::from(previous.amount))
                    .ok_or(ProtocolError::Overflow)?;
                if start < previous_end && u128::from(previous.offset) < end {
                    return Err(ProtocolError::OverlappingPortion);
                }
            }
            total = total
                .checked_add(u128::from(portion.amount))
                .ok_or(ProtocolError::Overflow)?;
        }
        if total != u128::from(max_debit) {
            return Err(ProtocolError::PartitionMismatch);
        }
        Ok(())
    }

    /// Length-tagged ordered rows, with exact domain and held debit. Row order is
    /// part of the proposed decision; a retry cannot silently reorder it.
    pub fn encode_into(
        &self,
        domain: &Domain,
        max_debit: u64,
        output: &mut [u8],
    ) -> Result<usize, ProtocolError> {
        domain.validate()?;
        self.validate(max_debit)?;
        let count = u32::try_from(self.portions.len()).map_err(|_| ProtocolError::Overflow)?;
        let len = self
            .portions
            .len()
            .checked_mul(49)
            .and_then(|rows| rows.checked_add(345))
            .ok_or(ProtocolError::Overflow)?;
        let bytes = output.get_mut(..len).ok_or(ProtocolError::InvalidLength)?;
        bytes[..8].copy_from_slice(b"KERBAP01");
        domain.encode_into(&mut bytes[8..333])?;
        bytes[333..341].copy_from_slice(&max_debit.to_le_bytes());
        bytes[341..345].copy_from_slice(&count.to_le_bytes());
        for (portion, row) in self
            .portions
            .iter()
            .zip(bytes[345..].as_chunks_mut::<49>().0)
        {
            row[..32].copy_from_slice(&portion.portion);
            row[32..40].copy_from_slice(&portion.offset.to_le_bytes());
            row[40..48].copy_from_slice(&portion.amount.to_le_bytes());
            row[48] = portion.kind as u8;
        }
        Ok(len)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum NativeIntentKind {
    SellerPayout = 1,
    BuyerRefund = 2,
    SponsorFee = 3,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum Disposition {
    Available = 1,
    Prepared = 2,
    EpochEncumbered = 3,
    SellerLiability = 4,
    BuyerUnused = 5,
    Excluded = 6,
    FencedAborted = 7,
    SafelyCancelled = 8,
    FirstLegPrepared = 9,
    SplReleased = 10,
    NativePending = 11,
    FinalPayout = 12,
    FinalRefund = 13,
    Disputed = 14,
    SponsorAvailable = 15,
}

pub const NATIVE_INTENT_LEN: usize = 570;

/// A proposed native transfer, NOT approval, signature, broadcast or payment.
/// `operation.effects` must commit these exact fields via `effects_digest`.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct NativeIntent {
    pub operation: Operation,
    pub kind: NativeIntentKind,
    pub recipient: [u8; 43],
    pub amount: u64,
    pub inventory_scope: Id,
}

/// Explicit consumer-supplied state, not a proof or an authenticated constructor.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct NativeLiability {
    pub domain: Domain,
    pub entity: Id,
    pub portion: Id,
    pub disposition: Disposition,
    pub recipient: [u8; 43],
    pub amount: u64,
    pub inventory_scope: Id,
    pub live_intent: Option<Id>,
}

/// Exact activation predicates over producer/journal data. Hashes and chunk
/// counts do not establish MPC authenticity, unanimity or durable activation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AllocationActivation {
    pub domain: Domain,
    pub allocation: Id,
    pub expected_chunks: u32,
    pub authenticated_chunks: u32,
    pub finalized_allocation: Id,
    pub activated_allocation: Id,
    pub acknowledgement_head: Id,
}
impl AllocationActivation {
    pub fn validate(&self, domain: &Domain) -> Result<(), ProtocolError> {
        domain.validate()?;
        if self.domain != *domain {
            return Err(ProtocolError::DomainMismatch);
        }
        if self.allocation == [0; 32]
            || self.expected_chunks == 0
            || self.authenticated_chunks != self.expected_chunks
            || self.finalized_allocation != self.allocation
            || self.activated_allocation != self.allocation
            || self.acknowledgement_head == [0; 32]
        {
            return Err(ProtocolError::EvidenceMismatch);
        }
        Ok(())
    }
}

/// Borrows consumer-owned facts for temporary policy validation; not serialized.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RefundEvidence<'a> {
    FinalUnused(&'a AllocationActivation),
    Excluded {
        domain: &'a Domain,
        portion: Id,
        decision: Id,
    },
    FencedAbort {
        domain: &'a Domain,
        portion: Id,
        fence: Id,
    },
    /// The producer must independently establish unanimous retained custody
    /// history with no potentially live native spend; a nonzero head is not proof.
    SafelyCancelled {
        domain: &'a Domain,
        portion: Id,
        cancellation: &'a ChainObservation,
        cancellation_operation: &'a Operation,
        environment: ObservationEnvironment,
        custody_head: Id,
    },
}

/// Observed and expected fields are deliberately distinct inputs. Consumers
/// must pin expectations from immutable liabilities and validate producer facts;
/// filling both from one untrusted request provides no independent evidence.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SplReleaseEvidence {
    pub domain: Domain,
    pub entity: Id,
    pub portion: Id,
    pub recipient: Id,
    pub base_atoms: u64,
    pub expected_recipient: Id,
    pub expected_base_atoms: u64,
    pub release: ChainObservation,
    pub release_operation: Operation,
    pub environment: ObservationEnvironment,
    pub activation: AllocationActivation,
}

/// Borrows consumer-owned liabilities and evidence without copying large records.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum NativeIntentEvidence<'a> {
    SellerPayout {
        liability: &'a NativeLiability,
        spl: &'a SplReleaseEvidence,
    },
    BuyerRefund {
        liability: &'a NativeLiability,
        refund: &'a RefundEvidence<'a>,
    },
    SponsorFee {
        liability: &'a NativeLiability,
        operator: Id,
        authorized_operator: Id,
        sponsor_scope: Id,
    },
}

impl NativeIntent {
    pub fn effects_digest(&self) -> Result<Id, ProtocolError> {
        let mut hash = Sha256::new();
        hash.update(b"KERBNE01");
        hash.update(self.operation.id()?);
        hash.update([self.kind as u8]);
        hash.update(self.recipient);
        hash.update(self.amount.to_le_bytes());
        hash.update(self.inventory_scope);
        Ok(hash.finalize().into())
    }

    fn check_record(&self) -> Result<(), ProtocolError> {
        self.operation.validate()?;
        if self.operation.transition != Transition::PrepareNative {
            return Err(ProtocolError::InvalidTransition);
        }
        if self.amount == 0 {
            return Err(ProtocolError::ZeroAmount);
        }
        if self.operation.portion == [0; 32]
            || self.recipient == [0; 43]
            || self.inventory_scope == [0; 32]
            || self.operation.effects != self.effects_digest()?
        {
            return Err(ProtocolError::EvidenceMismatch);
        }
        Ok(())
    }

    pub fn signing_bytes(&self) -> Result<[u8; ACK_SIGNING_LEN], ProtocolError> {
        let mut bytes = [0; NATIVE_INTENT_LEN];
        self.encode_into(&mut bytes)?;
        Ok(signing_message(SignatureRole::NativeIntent, sha256(&bytes)))
    }

    pub fn encode_into(&self, output: &mut [u8]) -> Result<usize, ProtocolError> {
        self.check_record()?;
        let bytes = output
            .get_mut(..NATIVE_INTENT_LEN)
            .ok_or(ProtocolError::InvalidLength)?;
        bytes[..8].copy_from_slice(b"KERBNI01");
        self.operation.encode_into(&mut bytes[8..486])?;
        bytes[486] = self.kind as u8;
        bytes[487..530].copy_from_slice(&self.recipient);
        bytes[530..538].copy_from_slice(&self.amount.to_le_bytes());
        bytes[538..570].copy_from_slice(&self.inventory_scope);
        Ok(NATIVE_INTENT_LEN)
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, ProtocolError> {
        check_frame(bytes, NATIVE_INTENT_LEN, b"KERBNI01")?;
        let kind = match bytes[486] {
            1 => NativeIntentKind::SellerPayout,
            2 => NativeIntentKind::BuyerRefund,
            3 => NativeIntentKind::SponsorFee,
            _ => return Err(ProtocolError::InvalidTransition),
        };
        let intent = Self {
            operation: Operation::decode(&bytes[8..486])?,
            kind,
            recipient: read_array(bytes, 487)?,
            amount: u64::from_le_bytes(read_array(bytes, 530)?),
            inventory_scope: read_array(bytes, 538)?,
        };
        intent.check_record()?;
        Ok(intent)
    }

    /// Data-policy validation only. This does not authenticate the liability,
    /// evidence producer, retained custody head, chain finality or MPC result.
    /// The ledger and custody must independently pin and authenticate those facts
    /// and persist exact unanimous intents/input locks before any signing handoff.
    pub fn validate(
        &self,
        domain: &Domain,
        evidence: &NativeIntentEvidence<'_>,
    ) -> Result<(), ProtocolError> {
        self.check_record()?;
        if self.operation.domain != *domain {
            return Err(ProtocolError::DomainMismatch);
        }
        let liability = match evidence {
            NativeIntentEvidence::SellerPayout { liability, .. }
            | NativeIntentEvidence::BuyerRefund { liability, .. }
            | NativeIntentEvidence::SponsorFee { liability, .. } => liability,
        };
        if liability.domain != *domain {
            return Err(ProtocolError::DomainMismatch);
        }
        if liability.entity != self.operation.entity
            || liability.portion != self.operation.portion
            || liability.recipient != self.recipient
            || liability.amount != self.amount
            || liability.inventory_scope != self.inventory_scope
        {
            return Err(ProtocolError::EvidenceMismatch);
        }
        if let Some(live) = liability.live_intent
            && live != self.operation.id()?
        {
            return Err(ProtocolError::CompetingIntent);
        }
        match (self.kind, evidence) {
            (NativeIntentKind::SellerPayout, NativeIntentEvidence::SellerPayout { spl, .. }) => {
                if liability.disposition != Disposition::SellerLiability {
                    return Err(ProtocolError::IntentNotPermitted);
                }
                if self.inventory_scope != domain.pair {
                    return Err(ProtocolError::EvidenceMismatch);
                }
                check_spl_release(spl, &self.operation, domain)
            }
            (NativeIntentKind::BuyerRefund, NativeIntentEvidence::BuyerRefund { refund, .. }) => {
                if self.inventory_scope != domain.pair {
                    return Err(ProtocolError::EvidenceMismatch);
                }
                check_refund(refund, liability.disposition, &self.operation, domain)
            }
            (
                NativeIntentKind::SponsorFee,
                NativeIntentEvidence::SponsorFee {
                    operator,
                    authorized_operator,
                    sponsor_scope,
                    ..
                },
            ) => {
                if liability.disposition != Disposition::SponsorAvailable {
                    return Err(ProtocolError::IntentNotPermitted);
                }
                if operator == &[0; 32]
                    || operator != authorized_operator
                    || sponsor_scope == &domain.pair
                    || *sponsor_scope != self.inventory_scope
                {
                    return Err(ProtocolError::EvidenceMismatch);
                }
                Ok(())
            }
            _ => Err(ProtocolError::IntentNotPermitted),
        }
    }
}

fn check_scope(
    operation: &Operation,
    expected: &Operation,
    domain: &Domain,
) -> Result<(), ProtocolError> {
    operation.validate()?;
    if operation.domain != *domain {
        return Err(ProtocolError::DomainMismatch);
    }
    if operation.entity != expected.entity || operation.portion != expected.portion {
        return Err(ProtocolError::EvidenceMismatch);
    }
    Ok(())
}

fn check_spl_release(
    spl: &SplReleaseEvidence,
    intent: &Operation,
    domain: &Domain,
) -> Result<(), ProtocolError> {
    if spl.domain != *domain {
        return Err(ProtocolError::DomainMismatch);
    }
    if spl.entity != intent.entity
        || spl.portion != intent.portion
        || spl.base_atoms == 0
        || spl.recipient == [0; 32]
        || spl.recipient != spl.expected_recipient
        || spl.base_atoms != spl.expected_base_atoms
        || spl.release_operation.transition != Transition::ReleaseSpl
    {
        return Err(ProtocolError::EvidenceMismatch);
    }
    check_scope(&spl.release_operation, intent, domain)?;
    spl.activation.validate(domain)?;
    spl.release.matches(
        &spl.release_operation,
        spl.environment,
        ChainCommitment::Finalized,
    )
}

fn check_refund(
    refund: &RefundEvidence<'_>,
    disposition: Disposition,
    intent: &Operation,
    domain: &Domain,
) -> Result<(), ProtocolError> {
    match refund {
        RefundEvidence::FinalUnused(activation) => {
            if disposition != Disposition::BuyerUnused {
                return Err(ProtocolError::IntentNotPermitted);
            }
            activation.validate(domain)
        }
        RefundEvidence::Excluded {
            domain: fact_domain,
            portion,
            decision,
        }
        | RefundEvidence::FencedAbort {
            domain: fact_domain,
            portion,
            fence: decision,
        } => {
            let expected = match refund {
                RefundEvidence::Excluded { .. } => Disposition::Excluded,
                _ => Disposition::FencedAborted,
            };
            if disposition != expected {
                return Err(ProtocolError::IntentNotPermitted);
            }
            if *fact_domain != domain {
                return Err(ProtocolError::DomainMismatch);
            }
            if *portion != intent.portion || *decision == [0; 32] {
                return Err(ProtocolError::EvidenceMismatch);
            }
            Ok(())
        }
        RefundEvidence::SafelyCancelled {
            domain: fact_domain,
            portion,
            cancellation,
            cancellation_operation,
            environment,
            custody_head,
        } => {
            if disposition != Disposition::SafelyCancelled {
                return Err(ProtocolError::IntentNotPermitted);
            }
            if *fact_domain != domain {
                return Err(ProtocolError::DomainMismatch);
            }
            if *portion != intent.portion
                || *custody_head == [0; 32]
                || cancellation_operation.transition != Transition::CancelFill
            {
                return Err(ProtocolError::EvidenceMismatch);
            }
            check_scope(cancellation_operation, intent, domain)?;
            cancellation.matches(
                cancellation_operation,
                *environment,
                ChainCommitment::Finalized,
            )
        }
    }
}
