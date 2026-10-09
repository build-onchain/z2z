use std::fmt;

use orchard::{Anchor, Note, keys::FullViewingKey, note::Nullifier, tree::MerklePath};
use pczt::Pczt;
use zcash_primitives::transaction::{Authorization, TransactionData};
use ziquid_proofs::native_relation::{self, NativeRelationError, OwnedInputFacts};

use crate::{AuthoringError, IronwoodTransaction};

/// Caller-owned positive-value note, FVK and anchored witness. This validates the
/// local relation, not the origin of the note or anchor admissibility on a chain.
#[derive(Clone)]
pub struct OwnedInput {
    note: Note,
    fvk: FullViewingKey,
    merkle_path: MerklePath,
    anchor: Anchor,
}

impl fmt::Debug for OwnedInput {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("OwnedInput([redacted])")
    }
}

impl OwnedInput {
    pub fn new(
        note: Note,
        fvk: FullViewingKey,
        merkle_path: MerklePath,
        anchor: Anchor,
    ) -> Result<Self, AuthoringError> {
        native_relation::validate_owned_input(&OwnedInputFacts {
            note: &note, full_viewing_key: &fvk, merkle_path: &merkle_path, anchor,
        }).map_err(relation_error)?;
        Ok(Self {
            note,
            fvk,
            merkle_path,
            anchor,
        })
    }

    pub fn note(&self) -> &Note {
        &self.note
    }
    pub fn full_viewing_key(&self) -> &FullViewingKey {
        &self.fvk
    }
    pub fn merkle_path(&self) -> &MerklePath {
        &self.merkle_path
    }
    pub fn anchor(&self) -> Anchor {
        self.anchor
    }
    pub fn nullifier(&self) -> Nullifier {
        self.note.nullifier(&self.fvk)
    }
}

/// Wallet-local sender opening. No receiver IVK, master OVK or spending key is required.
/// Its bytes, locator, plaintext and random seed must never be sent to a public log.
pub struct SenderOutputWitness {
    pub(crate) action_index: usize,
    pub(crate) note: Note,
    pub(crate) memo: [u8; 512],
}

impl fmt::Debug for SenderOutputWitness {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("SenderOutputWitness([redacted])")
    }
}

/// Private U custody artifact captured before any PCZT redaction. The complete
/// private PCZT retains every input/dummy opening, randomizer and output opening
/// for the application prover; it is NOT a preparation certificate for S.
pub struct PayoutWitness {
    pub(crate) input: OwnedInput,
    pub(crate) private_pczt_bytes: Vec<u8>,
    pub(crate) effect_id: [u8; 32],
    pub(crate) outputs: Vec<SenderOutputWitness>,
    pub(crate) requested_output_actions: Vec<usize>,
}

impl fmt::Debug for PayoutWitness {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("PayoutWitness([redacted])")
    }
}

/// Full sender-recovered plaintext, locally authenticated to an exact ciphertext.
pub struct RecoveredOutput {
    note: Note,
    memo: [u8; 512],
}

impl fmt::Debug for RecoveredOutput {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("RecoveredOutput([redacted])")
    }
}

impl RecoveredOutput {
    pub fn note(&self) -> &Note {
        &self.note
    }
    pub fn recipient(&self) -> orchard::Address {
        self.note.recipient()
    }
    pub fn value(&self) -> u64 {
        self.note.value().inner()
    }
    pub fn memo(&self) -> &[u8; 512] {
        &self.memo
    }
}

impl PayoutWitness {
    /// Restore caller-local custody, never a source/preparation certificate.
    /// Every private action opening and exact output ciphertext is validated.
    /// The authenticated caller mapping preserves requested order, including zero outputs.
    pub fn restore(
        input: OwnedInput,
        private_pczt_bytes: Vec<u8>,
        requested_output_actions: Vec<usize>,
    ) -> Result<Self, AuthoringError> {
        let restored = native_relation::restore_funding(
            &private_pczt_bytes,
            &OwnedInputFacts {
                note: input.note(), full_viewing_key: input.full_viewing_key(),
                merkle_path: input.merkle_path(), anchor: input.anchor(),
            },
            &requested_output_actions,
        ).map_err(relation_error)?;
        Ok(Self {
            input, private_pczt_bytes, effect_id: restored.effect_id,
            outputs: restored.outputs.into_iter().map(|output| SenderOutputWitness {
                action_index: output.action_index, note: output.note, memo: *output.memo,
            }).collect(),
            requested_output_actions,
        })
    }

    /// Exact builder metadata, not inferred from action zero or positive values.
    pub fn requested_output_actions(&self) -> &[usize] {
        &self.requested_output_actions
    }

    /// Explicit private persistence/prover boundary. Caller owns encryption,
    /// access control and retention; this is never part of the S packet.
    pub fn private_pczt_bytes(&self) -> &[u8] {
        &self.private_pczt_bytes
    }
    pub fn owned_input(&self) -> &OwnedInput {
        &self.input
    }
    pub fn effect_id(&self) -> [u8; 32] {
        self.effect_id
    }

    /// Recover the nth caller-requested output from the redacted exact P PCZT.
    pub fn recover_pczt_output(
        &self,
        pczt_bytes: &[u8],
        requested_index: usize,
    ) -> Result<RecoveredOutput, AuthoringError> {
        let effects = Pczt::parse(pczt_bytes)
            .map_err(|_| AuthoringError::InvalidPczt)?
            .into_effects()
            .map_err(|_| AuthoringError::InvalidPczt)?;
        self.recover_from_effects(&effects, requested_index)
    }

    /// Independent sender route over full transaction bytes after authorization.
    /// Local ciphertext recovery alone does not prove inclusion or consideration.
    pub fn recover_transaction_output(
        &self,
        transaction: &IronwoodTransaction,
        requested_index: usize,
    ) -> Result<RecoveredOutput, AuthoringError> {
        self.recover_from_effects(transaction.transaction(), requested_index)
    }

    fn recover_from_effects<A: Authorization>(
        &self,
        effects: &TransactionData<A>,
        requested_index: usize,
    ) -> Result<RecoveredOutput, AuthoringError> {
        if effect_id(effects) != self.effect_id {
            return Err(AuthoringError::EffectsMismatch);
        }
        if effects.ironwood_bundle().ok_or(AuthoringError::InvalidPczt)?.anchor() != &self.input.anchor() {
            return Err(AuthoringError::AnchorMismatch);
        }
        let index = *self
            .requested_output_actions
            .get(requested_index)
            .ok_or(AuthoringError::InvalidOutputIndex)?;
        let witness = self
            .outputs
            .get(index)
            .ok_or(AuthoringError::InvalidOutputIndex)?;
        if witness.action_index != index {
            return Err(AuthoringError::InvalidOutputIndex);
        }
        let bundle = effects
            .ironwood_bundle()
            .ok_or(AuthoringError::InvalidPczt)?;
        let action = bundle
            .actions()
            .get(index)
            .ok_or(AuthoringError::InvalidOutputIndex)?;
        witness.recover(action)
    }
}

impl SenderOutputWitness {
    pub(crate) fn recover<A>(
        &self,
        action: &orchard::Action<A>,
    ) -> Result<RecoveredOutput, AuthoringError> {
        let memo = native_relation::recover_action_output(action, &self.note, Some(&self.memo))
            .map_err(|_| AuthoringError::InvalidOutputCiphertext)?;
        Ok(RecoveredOutput { note: self.note, memo: *memo })
    }
}

pub(crate) fn effect_id<A: Authorization>(effects: &TransactionData<A>) -> [u8; 32] {
    native_relation::effect_id(effects)
}

pub(crate) fn relation_error(error: NativeRelationError) -> AuthoringError {
    use NativeRelationError as E;
    match error {
        E::WrongNoteVersion => AuthoringError::WrongNoteVersion,
        E::InvalidInputValue => AuthoringError::InvalidInputValue,
        E::InputNotOwned => AuthoringError::InputNotOwned,
        E::AnchorMismatch => AuthoringError::AnchorMismatch,
        E::InvalidHeight => AuthoringError::InvalidHeight,
        E::WrongBranch => AuthoringError::WrongBranch,
        E::InputMismatch | E::NativeVerification | E::DummySpendKey => AuthoringError::InvalidInputRelation,
        E::InvalidOutputIndex => AuthoringError::InvalidOutputIndex,
        E::CiphertextMismatch | E::OutputMismatch => AuthoringError::InvalidOutputCiphertext,
        E::EffectsChanged => AuthoringError::EffectsMismatch,
        E::ValueBalanceMismatch | E::FeeMismatch => AuthoringError::UnbalancedOutputs,
        _ => AuthoringError::InvalidPczt,
    }
}
