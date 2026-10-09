use super::domain::{check_frame, read_array};
use super::{Domain, Id, ProtocolError, Units, sha256};
use sha2::{Digest, Sha256};

pub const OPERATION_LEN: usize = 478;
pub const DECISION_LEN: usize = 550;
pub const ACK_SIGNING_LEN: usize = 64;
pub const ACKNOWLEDGEMENT_LEN: usize = 654;
pub const FUNDING_CLAIM_LEN: usize = 646;
pub const ADMISSION_HOLD_LEN: usize = 542;
pub const EPOCH_DECISION_LEN: usize = 523;
pub const FILL_INTENT_LEN: usize = 534;
pub const CHAIN_OBSERVATION_LEN: usize = 114;
pub const APPLICATION_SIGNATURE_DOMAIN: Id = *b"KERB_ED25519_APPLICATION_V1\0\0\0\0\0";
pub const DECISION_SIGNATURE_DOMAIN: Id = *b"KERB_ED25519_DECISION_V1\0\0\0\0\0\0\0\0";
pub const FUNDING_SIGNATURE_DOMAIN: Id = *b"KERB_ED25519_FUNDING_V1\0\0\0\0\0\0\0\0\0";
pub const NATIVE_SIGNATURE_DOMAIN: Id = *b"KERB_ED25519_NATIVE_V1\0\0\0\0\0\0\0\0\0\0";

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum Transition {
    InitializePair = 1,
    OpenEpoch = 2,
    LockSeller = 3,
    PrepareSeller = 4,
    PrepareHold = 5,
    CommitEpoch = 6,
    AbortEpoch = 7,
    RecordAllocation = 8,
    ActivateAllocation = 9,
    PrepareFill = 10,
    ReleaseSpl = 11,
    CancelFill = 12,
    ReturnUnused = 13,
    IssueCredit = 14,
    ReserveInputs = 15,
    PrepareNative = 16,
    ObserveNative = 17,
}
impl TryFrom<u8> for Transition {
    type Error = ProtocolError;
    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            1 => Ok(Self::InitializePair),
            2 => Ok(Self::OpenEpoch),
            3 => Ok(Self::LockSeller),
            4 => Ok(Self::PrepareSeller),
            5 => Ok(Self::PrepareHold),
            6 => Ok(Self::CommitEpoch),
            7 => Ok(Self::AbortEpoch),
            8 => Ok(Self::RecordAllocation),
            9 => Ok(Self::ActivateAllocation),
            10 => Ok(Self::PrepareFill),
            11 => Ok(Self::ReleaseSpl),
            12 => Ok(Self::CancelFill),
            13 => Ok(Self::ReturnUnused),
            14 => Ok(Self::IssueCredit),
            15 => Ok(Self::ReserveInputs),
            16 => Ok(Self::PrepareNative),
            17 => Ok(Self::ObserveNative),
            _ => Err(ProtocolError::InvalidTransition),
        }
    }
}

/// All roles use ordinary RFC8032 Ed25519. Arcis and native spend signatures
/// are different schemes and are not accepted by these business records.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SignatureRole {
    Application,
    BusinessDecision,
    FundingClaim,
    NativeIntent,
}
impl SignatureRole {
    fn prefix(self) -> Id {
        match self {
            Self::Application => APPLICATION_SIGNATURE_DOMAIN,
            Self::BusinessDecision => DECISION_SIGNATURE_DOMAIN,
            Self::FundingClaim => FUNDING_SIGNATURE_DOMAIN,
            Self::NativeIntent => NATIVE_SIGNATURE_DOMAIN,
        }
    }
}

pub(crate) fn signing_message(role: SignatureRole, digest: Id) -> [u8; ACK_SIGNING_LEN] {
    let mut bytes = [0; ACK_SIGNING_LEN];
    bytes[..32].copy_from_slice(&role.prefix());
    bytes[32..].copy_from_slice(&digest);
    bytes
}

pub(crate) fn copy_message(
    message: &[u8; ACK_SIGNING_LEN],
    output: &mut [u8],
) -> Result<usize, ProtocolError> {
    output
        .get_mut(..ACK_SIGNING_LEN)
        .ok_or(ProtocolError::InvalidLength)?
        .copy_from_slice(message);
    Ok(ACK_SIGNING_LEN)
}

/// An immutable proposed transition, not a state-machine execution or chain fact.
/// `effects` commits exact consumer-owned effects. The stable identity excludes
/// only effects so persistence can reject same-ID/different-body retries.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Operation {
    pub domain: Domain,
    pub entity: Id,
    pub portion: Id,
    pub intent: Id,
    pub generation: u64,
    pub prior_version: u64,
    pub transition: Transition,
    pub effects: Id,
}
impl Operation {
    pub fn validate(&self) -> Result<(), ProtocolError> {
        self.domain.validate()?;
        if self.generation == 0 {
            return Err(ProtocolError::InvalidGeneration);
        }
        if self.entity == [0; 32] || self.intent == [0; 32] || self.effects == [0; 32] {
            return Err(ProtocolError::EvidenceMismatch);
        }
        Ok(())
    }

    /// Stable business identity is computable before effects are committed.
    /// This does not validate a complete operation or enable its signature.
    pub fn id(&self) -> Result<Id, ProtocolError> {
        if self.generation == 0 {
            return Err(ProtocolError::InvalidGeneration);
        }
        if self.entity == [0; 32] || self.intent == [0; 32] {
            return Err(ProtocolError::EvidenceMismatch);
        }
        let mut domain = [0; super::DOMAIN_LEN];
        self.domain.encode_into(&mut domain)?;
        let mut hash = Sha256::new();
        hash.update(b"KERBID01");
        hash.update(domain);
        hash.update(self.entity);
        hash.update(self.portion);
        hash.update(self.intent);
        hash.update(self.generation.to_le_bytes());
        hash.update(self.prior_version.to_le_bytes());
        hash.update([self.transition as u8]);
        Ok(hash.finalize().into())
    }

    pub fn digest(&self) -> Result<Id, ProtocolError> {
        let mut bytes = [0; OPERATION_LEN];
        self.encode_into(&mut bytes)?;
        Ok(sha256(&bytes))
    }

    pub fn encode_into(&self, output: &mut [u8]) -> Result<usize, ProtocolError> {
        self.validate()?;
        let bytes = output
            .get_mut(..OPERATION_LEN)
            .ok_or(ProtocolError::InvalidLength)?;
        bytes[..8].copy_from_slice(b"KERBOP01");
        self.domain.encode_into(&mut bytes[8..333])?;
        bytes[333..365].copy_from_slice(&self.entity);
        bytes[365..397].copy_from_slice(&self.portion);
        bytes[397..429].copy_from_slice(&self.intent);
        bytes[429..437].copy_from_slice(&self.generation.to_le_bytes());
        bytes[437..445].copy_from_slice(&self.prior_version.to_le_bytes());
        bytes[445] = self.transition as u8;
        bytes[446..478].copy_from_slice(&self.effects);
        Ok(OPERATION_LEN)
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, ProtocolError> {
        check_frame(bytes, OPERATION_LEN, b"KERBOP01")?;
        let operation = Self {
            domain: Domain::decode(&bytes[8..333])?,
            entity: read_array(bytes, 333)?,
            portion: read_array(bytes, 365)?,
            intent: read_array(bytes, 397)?,
            generation: u64::from_le_bytes(read_array(bytes, 429)?),
            prior_version: u64::from_le_bytes(read_array(bytes, 437)?),
            transition: Transition::try_from(bytes[445])?,
            effects: read_array(bytes, 446)?,
        };
        operation.validate()?;
        Ok(operation)
    }

    pub fn signing_bytes(
        &self,
        role: SignatureRole,
    ) -> Result<[u8; ACK_SIGNING_LEN], ProtocolError> {
        Ok(signing_message(role, self.digest()?))
    }

    pub fn signing_bytes_into(
        &self,
        role: SignatureRole,
        output: &mut [u8],
    ) -> Result<usize, ProtocolError> {
        copy_message(&self.signing_bytes(role)?, output)
    }
}

/// Exact CAS scope. Rotation may increase the writer generation, never reset
/// this entity/portion version or discard retained terminal markers.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct EntityVersion {
    pub domain: Domain,
    pub entity: Id,
    pub portion: Id,
    pub generation: u64,
    pub version: u64,
}
impl EntityVersion {
    pub fn check_next(&self, operation: &Operation) -> Result<u64, ProtocolError> {
        operation.validate()?;
        if self.domain != operation.domain {
            return Err(ProtocolError::DomainMismatch);
        }
        if self.entity != operation.entity || self.portion != operation.portion {
            return Err(ProtocolError::EvidenceMismatch);
        }
        if self.generation == 0
            || operation.generation < self.generation
            || operation.prior_version != self.version
        {
            return Err(ProtocolError::InvalidGeneration);
        }
        self.version.checked_add(1).ok_or(ProtocolError::Overflow)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Decision {
    pub operation: Operation,
    pub predecessor: Id,
    pub next_head: Id,
}
fn decision_head(predecessor: &Id, operation_digest: &Id) -> Id {
    let mut hash = Sha256::new();
    hash.update(b"KERBHD01");
    hash.update(predecessor);
    hash.update(operation_digest);
    hash.finalize().into()
}
impl Decision {
    pub fn new(operation: Operation, predecessor: Id) -> Result<Self, ProtocolError> {
        let next_head = decision_head(&predecessor, &operation.digest()?);
        Ok(Self {
            operation,
            predecessor,
            next_head,
        })
    }

    pub fn validate(&self) -> Result<(), ProtocolError> {
        if self.next_head != decision_head(&self.predecessor, &self.operation.digest()?) {
            return Err(ProtocolError::InvalidDecisionHead);
        }
        Ok(())
    }

    pub fn digest(&self) -> Result<Id, ProtocolError> {
        let mut bytes = [0; DECISION_LEN];
        self.encode_into(&mut bytes)?;
        Ok(sha256(&bytes))
    }

    pub fn signing_bytes(&self) -> Result<[u8; ACK_SIGNING_LEN], ProtocolError> {
        Ok(signing_message(
            SignatureRole::BusinessDecision,
            self.digest()?,
        ))
    }

    pub fn signing_bytes_into(&self, output: &mut [u8]) -> Result<usize, ProtocolError> {
        copy_message(&self.signing_bytes()?, output)
    }

    pub fn encode_into(&self, output: &mut [u8]) -> Result<usize, ProtocolError> {
        let bytes = output
            .get_mut(..DECISION_LEN)
            .ok_or(ProtocolError::InvalidLength)?;
        self.operation.encode_into(&mut bytes[8..486])?;
        if self.next_head != decision_head(&self.predecessor, &sha256(&bytes[8..486])) {
            return Err(ProtocolError::InvalidDecisionHead);
        }
        bytes[..8].copy_from_slice(b"KERBDC01");
        bytes[486..518].copy_from_slice(&self.predecessor);
        bytes[518..550].copy_from_slice(&self.next_head);
        Ok(DECISION_LEN)
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, ProtocolError> {
        check_frame(bytes, DECISION_LEN, b"KERBDC01")?;
        let decision = Self {
            operation: Operation::decode(&bytes[8..486])?,
            predecessor: read_array(bytes, 486)?,
            next_head: read_array(bytes, 518)?,
        };
        decision.validate()?;
        Ok(decision)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Acknowledgement {
    pub signer: Id,
    pub signature: [u8; 64],
    pub decision: Decision,
}
impl Acknowledgement {
    /// Codec only: decoding never authenticates the acknowledgement.
    pub fn encode_into(&self, output: &mut [u8]) -> Result<usize, ProtocolError> {
        let bytes = output
            .get_mut(..ACKNOWLEDGEMENT_LEN)
            .ok_or(ProtocolError::InvalidLength)?;
        self.decision.encode_into(&mut bytes[104..654])?;
        bytes[..8].copy_from_slice(b"KERBAK01");
        bytes[8..40].copy_from_slice(&self.signer);
        bytes[40..104].copy_from_slice(&self.signature);
        Ok(ACKNOWLEDGEMENT_LEN)
    }
    pub fn decode(bytes: &[u8]) -> Result<Self, ProtocolError> {
        check_frame(bytes, ACKNOWLEDGEMENT_LEN, b"KERBAK01")?;
        Ok(Self {
            signer: read_array(bytes, 8)?,
            signature: read_array(bytes, 40)?,
            decision: Decision::decode(&bytes[104..654])?,
        })
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SourceOccurrence {
    pub network: u8,
    pub pool: u8,
    pub txid: Id,
    pub action_index: u32,
}

/// Claimant-authorized data, NOT a source-history/spendability proof. The
/// evidence producer, receiver policy, controlled inventory and durable dedup
/// must be independently checked by the ledger before issuing any credit.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct FundingClaim {
    pub domain: Domain,
    pub occurrence: SourceOccurrence,
    pub claimant: Id,
    pub receiver: [u8; 43],
    pub value: u64,
    pub block_policy: Id,
    pub inventory_note: Id,
    pub evidence_digest: Id,
    pub credit_intent: Id,
    pub authorization: [u8; 64],
}
impl FundingClaim {
    pub fn validate(&self) -> Result<(), ProtocolError> {
        self.domain.validate()?;
        if self.occurrence.network != self.domain.source_network
            || self.occurrence.pool != self.domain.source_pool
        {
            return Err(ProtocolError::DomainMismatch);
        }
        if self.value == 0 {
            return Err(ProtocolError::ZeroAmount);
        }
        if self.occurrence.txid == [0; 32]
            || self.claimant == [0; 32]
            || self.receiver == [0; 43]
            || self.block_policy == [0; 32]
            || self.inventory_note == [0; 32]
            || self.evidence_digest == [0; 32]
            || self.credit_intent == [0; 32]
        {
            return Err(ProtocolError::EvidenceMismatch);
        }
        Ok(())
    }

    fn encode_unsigned(&self, bytes: &mut [u8; 582]) -> Result<(), ProtocolError> {
        self.validate()?;
        bytes[..8].copy_from_slice(b"KERBFC01");
        self.domain.encode_into(&mut bytes[8..333])?;
        bytes[333] = self.occurrence.network;
        bytes[334] = self.occurrence.pool;
        bytes[335..367].copy_from_slice(&self.occurrence.txid);
        bytes[367..371].copy_from_slice(&self.occurrence.action_index.to_le_bytes());
        bytes[371..403].copy_from_slice(&self.claimant);
        bytes[403..446].copy_from_slice(&self.receiver);
        bytes[446..454].copy_from_slice(&self.value.to_le_bytes());
        bytes[454..486].copy_from_slice(&self.block_policy);
        bytes[486..518].copy_from_slice(&self.inventory_note);
        bytes[518..550].copy_from_slice(&self.evidence_digest);
        bytes[550..582].copy_from_slice(&self.credit_intent);
        Ok(())
    }

    pub fn signing_bytes(&self) -> Result<[u8; ACK_SIGNING_LEN], ProtocolError> {
        let mut bytes = [0; 582];
        self.encode_unsigned(&mut bytes)?;
        Ok(signing_message(SignatureRole::FundingClaim, sha256(&bytes)))
    }

    pub fn encode_into(&self, output: &mut [u8]) -> Result<usize, ProtocolError> {
        let bytes = output
            .get_mut(..FUNDING_CLAIM_LEN)
            .ok_or(ProtocolError::InvalidLength)?;
        let unsigned: &mut [u8; 582] = (&mut bytes[..582])
            .try_into()
            .map_err(|_| ProtocolError::InvalidLength)?;
        self.encode_unsigned(unsigned)?;
        bytes[582..646].copy_from_slice(&self.authorization);
        Ok(FUNDING_CLAIM_LEN)
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, ProtocolError> {
        check_frame(bytes, FUNDING_CLAIM_LEN, b"KERBFC01")?;
        let claim = Self {
            domain: Domain::decode(&bytes[8..333])?,
            occurrence: SourceOccurrence {
                network: bytes[333],
                pool: bytes[334],
                txid: read_array(bytes, 335)?,
                action_index: u32::from_le_bytes(read_array(bytes, 367)?),
            },
            claimant: read_array(bytes, 371)?,
            receiver: read_array(bytes, 403)?,
            value: u64::from_le_bytes(read_array(bytes, 446)?),
            block_policy: read_array(bytes, 454)?,
            inventory_note: read_array(bytes, 486)?,
            evidence_digest: read_array(bytes, 518)?,
            credit_intent: read_array(bytes, 550)?,
            authorization: read_array(bytes, 582)?,
        };
        claim.validate()?;
        Ok(claim)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AdmissionHold {
    pub operation: Operation,
    pub owner: Id,
    pub amount: u64,
    pub units: Units,
}
impl AdmissionHold {
    pub fn validate(&self) -> Result<(), ProtocolError> {
        self.operation.validate()?;
        self.units.validate()?;
        if !matches!(
            self.operation.transition,
            Transition::PrepareHold | Transition::PrepareSeller
        ) {
            return Err(ProtocolError::InvalidTransition);
        }
        if self.amount == 0 {
            return Err(ProtocolError::ZeroAmount);
        }
        if self.owner == [0; 32] {
            return Err(ProtocolError::EvidenceMismatch);
        }
        Ok(())
    }
    pub fn encode_into(&self, output: &mut [u8]) -> Result<usize, ProtocolError> {
        self.validate()?;
        let bytes = output
            .get_mut(..ADMISSION_HOLD_LEN)
            .ok_or(ProtocolError::InvalidLength)?;
        bytes[..8].copy_from_slice(b"KERBAH01");
        self.operation.encode_into(&mut bytes[8..486])?;
        bytes[486..518].copy_from_slice(&self.owner);
        bytes[518..526].copy_from_slice(&self.amount.to_le_bytes());
        bytes[526..534].copy_from_slice(&self.units.base_atoms_per_lot.to_le_bytes());
        bytes[534..542].copy_from_slice(&self.units.quote_atoms_per_lot_tick.to_le_bytes());
        Ok(ADMISSION_HOLD_LEN)
    }
    pub fn signing_bytes(&self) -> Result<[u8; ACK_SIGNING_LEN], ProtocolError> {
        let mut bytes = [0; ADMISSION_HOLD_LEN];
        self.encode_into(&mut bytes)?;
        Ok(signing_message(SignatureRole::Application, sha256(&bytes)))
    }
    pub fn decode(bytes: &[u8]) -> Result<Self, ProtocolError> {
        check_frame(bytes, ADMISSION_HOLD_LEN, b"KERBAH01")?;
        let hold = Self {
            operation: Operation::decode(&bytes[8..486])?,
            owner: read_array(bytes, 486)?,
            amount: u64::from_le_bytes(read_array(bytes, 518)?),
            units: Units {
                base_atoms_per_lot: u64::from_le_bytes(read_array(bytes, 526)?),
                quote_atoms_per_lot_tick: u64::from_le_bytes(read_array(bytes, 534)?),
            },
        };
        hold.validate()?;
        Ok(hold)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum EpochOutcome {
    Commit = 1,
    Abort = 2,
    Final = 3,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct EpochDecision {
    pub operation: Operation,
    pub outcome: EpochOutcome,
    pub allocation_digest: Id,
    pub chunk_count: u32,
}
impl EpochDecision {
    pub fn validate(&self) -> Result<(), ProtocolError> {
        self.operation.validate()?;
        let valid = match self.outcome {
            EpochOutcome::Commit => {
                self.operation.transition == Transition::CommitEpoch
                    && self.allocation_digest == [0; 32]
                    && self.chunk_count == 0
            }
            EpochOutcome::Abort => {
                self.operation.transition == Transition::AbortEpoch
                    && self.allocation_digest == [0; 32]
                    && self.chunk_count == 0
            }
            EpochOutcome::Final => {
                self.operation.transition == Transition::RecordAllocation
                    && self.allocation_digest != [0; 32]
                    && self.chunk_count > 0
            }
        };
        if !valid {
            return Err(ProtocolError::EvidenceMismatch);
        }
        Ok(())
    }
    pub fn encode_into(&self, output: &mut [u8]) -> Result<usize, ProtocolError> {
        self.validate()?;
        let bytes = output
            .get_mut(..EPOCH_DECISION_LEN)
            .ok_or(ProtocolError::InvalidLength)?;
        bytes[..8].copy_from_slice(b"KERBED01");
        self.operation.encode_into(&mut bytes[8..486])?;
        bytes[486] = self.outcome as u8;
        bytes[487..519].copy_from_slice(&self.allocation_digest);
        bytes[519..523].copy_from_slice(&self.chunk_count.to_le_bytes());
        Ok(EPOCH_DECISION_LEN)
    }
    pub fn signing_bytes(&self) -> Result<[u8; ACK_SIGNING_LEN], ProtocolError> {
        let mut bytes = [0; EPOCH_DECISION_LEN];
        self.encode_into(&mut bytes)?;
        Ok(signing_message(
            SignatureRole::BusinessDecision,
            sha256(&bytes),
        ))
    }
    pub fn decode(bytes: &[u8]) -> Result<Self, ProtocolError> {
        check_frame(bytes, EPOCH_DECISION_LEN, b"KERBED01")?;
        let outcome = match bytes[486] {
            1 => EpochOutcome::Commit,
            2 => EpochOutcome::Abort,
            3 => EpochOutcome::Final,
            _ => return Err(ProtocolError::InvalidTransition),
        };
        let decision = Self {
            operation: Operation::decode(&bytes[8..486])?,
            outcome,
            allocation_digest: read_array(bytes, 487)?,
            chunk_count: u32::from_le_bytes(read_array(bytes, 519)?),
        };
        decision.validate()?;
        Ok(decision)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct FillIntent {
    pub operation: Operation,
    pub recipient: Id,
    pub base_atoms: u64,
    pub quote_atoms: u64,
}
impl FillIntent {
    pub fn validate(&self) -> Result<(), ProtocolError> {
        self.operation.validate()?;
        if self.operation.transition != Transition::PrepareFill {
            return Err(ProtocolError::InvalidTransition);
        }
        if self.base_atoms == 0 || self.quote_atoms == 0 {
            return Err(ProtocolError::ZeroAmount);
        }
        if self.recipient == [0; 32] || self.operation.portion == [0; 32] {
            return Err(ProtocolError::EvidenceMismatch);
        }
        Ok(())
    }
    pub fn encode_into(&self, output: &mut [u8]) -> Result<usize, ProtocolError> {
        self.validate()?;
        let bytes = output
            .get_mut(..FILL_INTENT_LEN)
            .ok_or(ProtocolError::InvalidLength)?;
        bytes[..8].copy_from_slice(b"KERBFI01");
        self.operation.encode_into(&mut bytes[8..486])?;
        bytes[486..518].copy_from_slice(&self.recipient);
        bytes[518..526].copy_from_slice(&self.base_atoms.to_le_bytes());
        bytes[526..534].copy_from_slice(&self.quote_atoms.to_le_bytes());
        Ok(FILL_INTENT_LEN)
    }
    pub fn signing_bytes(&self) -> Result<[u8; ACK_SIGNING_LEN], ProtocolError> {
        let mut bytes = [0; FILL_INTENT_LEN];
        self.encode_into(&mut bytes)?;
        Ok(signing_message(SignatureRole::Application, sha256(&bytes)))
    }
    pub fn decode(bytes: &[u8]) -> Result<Self, ProtocolError> {
        check_frame(bytes, FILL_INTENT_LEN, b"KERBFI01")?;
        let fill = Self {
            operation: Operation::decode(&bytes[8..486])?,
            recipient: read_array(bytes, 486)?,
            base_atoms: u64::from_le_bytes(read_array(bytes, 518)?),
            quote_atoms: u64::from_le_bytes(read_array(bytes, 526)?),
        };
        fill.validate()?;
        Ok(fill)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum ObservationEnvironment {
    LocalFixture = 1,
    Network = 2,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum ChainCommitment {
    Submitted = 1,
    Confirmed = 2,
    Finalized = 3,
}

/// An observed fact supplied by a producer. The codec and `matches` do not
/// verify a chain, transaction effects, inclusion or finality.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ChainObservation {
    pub environment: ObservationEnvironment,
    pub operation: Id,
    pub transaction: Id,
    pub slot: u64,
    pub commitment: ChainCommitment,
    pub effects: Id,
}
impl ChainObservation {
    pub fn matches(
        &self,
        operation: &Operation,
        environment: ObservationEnvironment,
        commitment: ChainCommitment,
    ) -> Result<(), ProtocolError> {
        if self.environment != environment
            || (self.commitment as u8) < commitment as u8
            || self.operation != operation.id()?
            || self.effects != operation.effects
            || self.transaction == [0; 32]
        {
            return Err(ProtocolError::EvidenceMismatch);
        }
        Ok(())
    }
    pub fn encode_into(&self, output: &mut [u8]) -> Result<usize, ProtocolError> {
        if self.operation == [0; 32] || self.transaction == [0; 32] || self.effects == [0; 32] {
            return Err(ProtocolError::EvidenceMismatch);
        }
        let bytes = output
            .get_mut(..CHAIN_OBSERVATION_LEN)
            .ok_or(ProtocolError::InvalidLength)?;
        bytes[..8].copy_from_slice(b"KERBCO01");
        bytes[8] = self.environment as u8;
        bytes[9..41].copy_from_slice(&self.operation);
        bytes[41..73].copy_from_slice(&self.transaction);
        bytes[73..81].copy_from_slice(&self.slot.to_le_bytes());
        bytes[81] = self.commitment as u8;
        bytes[82..114].copy_from_slice(&self.effects);
        Ok(CHAIN_OBSERVATION_LEN)
    }
    pub fn decode(bytes: &[u8]) -> Result<Self, ProtocolError> {
        check_frame(bytes, CHAIN_OBSERVATION_LEN, b"KERBCO01")?;
        let environment = match bytes[8] {
            1 => ObservationEnvironment::LocalFixture,
            2 => ObservationEnvironment::Network,
            _ => return Err(ProtocolError::EvidenceMismatch),
        };
        let commitment = match bytes[81] {
            1 => ChainCommitment::Submitted,
            2 => ChainCommitment::Confirmed,
            3 => ChainCommitment::Finalized,
            _ => return Err(ProtocolError::EvidenceMismatch),
        };
        let fact = Self {
            environment,
            operation: read_array(bytes, 9)?,
            transaction: read_array(bytes, 41)?,
            slot: u64::from_le_bytes(read_array(bytes, 73)?),
            commitment,
            effects: read_array(bytes, 82)?,
        };
        if fact.operation == [0; 32] || fact.transaction == [0; 32] || fact.effects == [0; 32] {
            return Err(ProtocolError::EvidenceMismatch);
        }
        Ok(fact)
    }
}

#[cfg(feature = "market-host")]
fn verify_message(
    message: &[u8; ACK_SIGNING_LEN],
    key: &Id,
    signature: &[u8; 64],
) -> Result<(), ProtocolError> {
    super::validate_authorization_key(key)?;
    super::validate_signature_encoding(signature)?;
    let key = ed25519_dalek::VerifyingKey::from_bytes(key)
        .map_err(|_| ProtocolError::InvalidAuthorizationKey)?;
    key.verify_strict(message, &ed25519_dalek::Signature::from_bytes(signature))
        .map_err(|_| ProtocolError::InvalidSignature)
}

/// Verifies only three distinct enrolled ordinary Ed25519 signatures on this
/// exact decision. Persistence, independent control, predecessor retention and
/// business predicates are the consumer's responsibilities, not this result.
#[cfg(feature = "market-host")]
pub fn verify_unanimous(
    decision: &Decision,
    acks: &[Acknowledgement],
    roster: &[Id; 3],
) -> Result<(), ProtocolError> {
    let message = decision.signing_bytes()?;
    if acks.len() != 3 {
        return Err(ProtocolError::MissingUnanimity);
    }
    if roster[0] == roster[1] || roster[0] == roster[2] || roster[1] == roster[2] {
        return Err(ProtocolError::DuplicateSigner);
    }
    for (index, ack) in acks.iter().enumerate() {
        if acks[..index]
            .iter()
            .any(|previous| previous.signer == ack.signer)
        {
            return Err(ProtocolError::DuplicateSigner);
        }
        if !roster.contains(&ack.signer) {
            return Err(ProtocolError::UnenrolledSigner);
        }
        if ack.decision != *decision {
            return Err(ProtocolError::WrongAcknowledgement);
        }
        verify_message(&message, &ack.signer, &ack.signature)?;
    }
    Ok(())
}

#[cfg(feature = "market-host")]
pub fn verify_operation(
    operation: &Operation,
    role: SignatureRole,
    key: &Id,
    signature: &[u8; 64],
) -> Result<(), ProtocolError> {
    verify_message(&operation.signing_bytes(role)?, key, signature)
}

#[cfg(feature = "market-host")]
pub fn verify_funding_claim(claim: &FundingClaim) -> Result<(), ProtocolError> {
    verify_message(
        &claim.signing_bytes()?,
        &claim.claimant,
        &claim.authorization,
    )
}
