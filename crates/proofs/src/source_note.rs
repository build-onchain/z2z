//! Owner-local Orchard-family membership and consumption in a fully validated
//! finite testnet prefix. This is not canonicality, freshness, finality, a SNARK,
//! a note/FVK derivation check, payment classification, or financial authority.
//! The unchanged aggregate journal does not commit to these local selections.

use std::{fmt, io::Read, ops::Range};

use incrementalmerkletree::{frontier::CommitmentTree, witness::IncrementalWitness};
use orchard::{
    note::{ExtractedNoteCommitment, Nullifier},
    tree::{Anchor, MerkleHashOrchard, MerklePath},
};
use zeroize::Zeroizing;

use crate::{
    genesis::{ShieldedPool, ledger::SproutTestnetLedger},
    header::HeaderTip,
    post_nu5_body::{PostNu5Block, PostNu5Transaction},
    source_replay::{JOURNAL_LEN, MAX_BLOCK_BYTES, MAX_BLOCK_COUNT, ReplayPhase, SourceReplayError, replay_framed_testnet_with},
    source_selection::post_nu5_transaction_ranges,
};

/// Exact zero-based funding action and BOTH independently held transaction IDs.
#[derive(Clone, Copy, Eq, PartialEq)]
pub struct SourceFundingLocator {
    pub block_height: u32,
    pub transaction_index: u32,
    pub action_index: u32,
    pub effect_id: [u8; 32],
    pub auth_digest: [u8; 32],
}

impl fmt::Debug for SourceFundingLocator {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.debug_struct("SourceFundingLocator").finish_non_exhaustive()
    }
}

/// The caller derives the commitment/nullifier relation owner-locally. Replay
/// authenticates the supplied values' occurrences, not that private derivation.
#[derive(Clone, Copy)]
pub struct SourceNoteSelection {
    pub pool: ShieldedPool,
    pub commitment: [u8; 32],
    pub nullifier: [u8; 32],
    pub funding: SourceFundingLocator,
}

impl fmt::Debug for SourceNoteSelection {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.debug_struct("SourceNoteSelection").finish_non_exhaustive()
    }
}

/// Fixed categories retain no transaction, note, locator or reader error bytes.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SourceNoteError {
    Replay(SourceReplayError),
    InvalidSelection,
    FundingNotFound,
    FundingMismatch,
    NullifierBeforeFunding,
    InvalidWitness,
}

impl From<SourceReplayError> for SourceNoteError {
    fn from(error: SourceReplayError) -> Self { Self::Replay(error) }
}

impl fmt::Display for SourceNoteError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Replay(error) => fmt::Display::fmt(error, formatter),
            Self::InvalidSelection => formatter.write_str("source note selection rejected"),
            Self::FundingNotFound => formatter.write_str("source note funding occurrence not found"),
            Self::FundingMismatch => formatter.write_str("source note funding occurrence differs"),
            Self::NullifierBeforeFunding => formatter.write_str("source note nullifier occurs before funding"),
            Self::InvalidWitness => formatter.write_str("source note witness is inconsistent with admitted ledger"),
        }
    }
}

impl std::error::Error for SourceNoteError {}

/// A fully admitted action occurrence, not a C/R/refund or payment classifier.
#[derive(Clone, Copy)]
pub struct SourceNoteOccurrence {
    block: HeaderTip,
    locator: SourceFundingLocator,
}

impl SourceNoteOccurrence {
    pub fn block(&self) -> HeaderTip { self.block }
    pub fn transaction_index(&self) -> u32 { self.locator.transaction_index }
    pub fn action_index(&self) -> u32 { self.locator.action_index }
    /// Internal/wire order, not RPC display order.
    pub fn effect_id(&self) -> [u8; 32] { self.locator.effect_id }
    pub fn auth_digest(&self) -> [u8; 32] { self.locator.auth_digest }
}

impl fmt::Debug for SourceNoteOccurrence {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.debug_struct("SourceNoteOccurrence").finish_non_exhaustive()
    }
}

/// Immutable terminal owner-local evidence. No public constructor, deserializer,
/// checkpoint import or conversion to a financial fact is provided.
pub struct FiniteValidatedPrefixNote {
    facts: FiniteValidatedPrefixNoteFacts,
    packets: [Option<Zeroizing<Vec<u8>>>; 3],
    funding_packet: usize,
    consuming_packet: Option<usize>,
    boundary: HeaderTip,
    boundary_journal: [u8; JOURNAL_LEN],
}

/// Selected occurrence and terminal membership, never a transaction's earlier
/// spend anchor. Only a completed full replay can construct these facts.
pub(crate) struct FiniteValidatedPrefixNoteFacts {
    selection: SourceNoteSelection,
    funding: SourceNoteOccurrence,
    merkle_path: MerklePath,
    anchor: Anchor,
    tree_count: u64,
    consumption: Option<SourceNoteOccurrence>,
}

impl FiniteValidatedPrefixNoteFacts {
    pub(crate) fn pool(&self) -> ShieldedPool { self.selection.pool }
    pub(crate) fn commitment(&self) -> [u8; 32] { self.selection.commitment }
    pub(crate) fn nullifier(&self) -> [u8; 32] { self.selection.nullifier }
    pub(crate) fn funding(&self) -> &SourceNoteOccurrence { &self.funding }
    pub(crate) fn position(&self) -> u32 { self.merkle_path.position() }
    pub(crate) fn merkle_path(&self) -> &MerklePath { &self.merkle_path }
    pub(crate) fn anchor(&self) -> Anchor { self.anchor }
    pub(crate) fn tree_count(&self) -> u64 { self.tree_count }
    pub(crate) fn consumption(&self) -> Option<&SourceNoteOccurrence> { self.consumption.as_ref() }
}

impl FiniteValidatedPrefixNote {
    pub fn pool(&self) -> ShieldedPool { self.facts.pool() }
    pub fn commitment(&self) -> [u8; 32] { self.facts.commitment() }
    pub fn nullifier(&self) -> [u8; 32] { self.facts.nullifier() }
    pub fn funding(&self) -> &SourceNoteOccurrence { self.facts.funding() }
    /// Exact canonical original bytes at `funding()`, from this same replay.
    /// Linkable owner-local evidence only; not a payment or financial fact.
    pub fn funding_transaction_bytes(&self) -> &[u8] {
        self.packets[self.funding_packet].as_ref().expect("sealed funding packet")
    }
    pub fn position(&self) -> u32 { self.facts.position() }
    pub fn merkle_path(&self) -> &MerklePath { self.facts.merkle_path() }
    /// Terminal admitted tree root, not the earlier funding or consumer anchor.
    pub fn anchor(&self) -> Anchor { self.facts.anchor() }
    pub fn tree_count(&self) -> u64 { self.facts.tree_count() }
    /// None means absent ONLY in this supplied validated prefix, not live unspent.
    /// Membership is retained and updated even after actual consumption.
    pub fn consumption(&self) -> Option<&SourceNoteOccurrence> { self.facts.consumption() }
    /// Exact original bytes at `consumption()`, or absence only in this prefix.
    pub fn consuming_transaction_bytes(&self) -> Option<&[u8]> {
        self.consuming_packet.map(|index| self.packets[index].as_ref().expect("sealed consuming packet").as_slice())
    }
    pub fn boundary(&self) -> HeaderTip { self.boundary }
    pub fn boundary_journal(&self) -> &[u8; JOURNAL_LEN] { &self.boundary_journal }
}

impl fmt::Debug for FiniteValidatedPrefixNote {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.debug_struct("FiniteValidatedPrefixNote").finish_non_exhaustive()
    }
}

/// Reuses authentic genesis, every full ledger transition, framing, budgets and
/// actual EOF. Candidate witness state is private and disposable. A later error
/// discards BOTH the owned replay ledger and tracker, publishing no capability;
/// this does not change atomicity of the standalone mutable ledger interface.
/// At most two original transaction packets are retained, each bounded by the
/// existing MAX_BLOCK_BYTES limit and erased on drop, including any later error.
pub fn replay_note_testnet(
    reader: &mut impl Read,
    max_blocks: u32,
    max_input_bytes: u64,
    selection: SourceNoteSelection,
) -> Result<FiniteValidatedPrefixNote, SourceNoteError> {
    let ReplayedNotes { notes: [note], packets, ledger, boundary_journal } =
        replay_notes_testnet(reader, max_blocks, max_input_bytes, [selection])?;
    let (facts, funding_packet, consuming_packet) = note.finish(&ledger)?;
    Ok(FiniteValidatedPrefixNote {
        facts, packets: packets.map(|packet| packet.map(|packet| packet.bytes)),
        funding_packet, consuming_packet, boundary: ledger.tip(), boundary_journal,
    })
}

/// Both note histories in one fully admitted prefix. F is retained once and is
/// simultaneously the origin's actual consumer and the selected J funder.
/// No constructor, checkpoint import or financial authority is exposed.
pub(crate) struct FiniteValidatedPrefixOriginJoint {
    origin: FiniteValidatedPrefixNoteFacts,
    joint: FiniteValidatedPrefixNoteFacts,
    packets: [Option<Zeroizing<Vec<u8>>>; 3],
    funding_packet: usize,
    consuming_packet: Option<usize>,
    boundary: HeaderTip,
}

impl FiniteValidatedPrefixOriginJoint {
    pub(crate) fn origin(&self) -> &FiniteValidatedPrefixNoteFacts { &self.origin }
    pub(crate) fn joint(&self) -> &FiniteValidatedPrefixNoteFacts { &self.joint }
    pub(crate) fn funding_transaction_bytes(&self) -> &[u8] {
        self.packets[self.funding_packet].as_ref().expect("sealed shared F packet")
    }
    pub(crate) fn consuming_transaction_bytes(&self) -> Option<&[u8]> {
        self.consuming_packet.map(|index| self.packets[index].as_ref().expect("sealed J consuming packet").as_slice())
    }
    pub(crate) fn boundary(&self) -> HeaderTip { self.boundary }
}

impl fmt::Debug for FiniteValidatedPrefixOriginJoint {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.debug_struct("FiniteValidatedPrefixOriginJoint").finish_non_exhaustive()
    }
}

/// Caller-local cmx/NF derivations are checked elsewhere; this entrypoint joins
/// their actual occurrences through the existing complete ledger. Boundary
/// paths are not substituted for F's or the consumer's independent spend anchor.
/// At most three unique original packets, each <= MAX_BLOCK_BYTES, survive;
/// every retained byte is erased on drop, including later body/EOF rejection.
pub(crate) fn replay_origin_joint_testnet(
    reader: &mut impl Read,
    max_blocks: u32,
    max_input_bytes: u64,
    origin: SourceNoteSelection,
    joint: SourceNoteSelection,
) -> Result<FiniteValidatedPrefixOriginJoint, SourceNoteError> {
    // An earlier action in the same transaction is not an earlier funding tx.
    if (origin.funding.block_height, origin.funding.transaction_index)
        >= (joint.funding.block_height, joint.funding.transaction_index)
    {
        return Err(SourceNoteError::InvalidSelection);
    }
    let ReplayedNotes { notes: [origin, joint], packets, ledger, .. } =
        replay_notes_testnet(reader, max_blocks, max_input_bytes, [origin, joint])?;
    check_origin_joint_link(&origin.state, &joint.state)?;
    let (origin, _, origin_consuming_packet) = origin.finish(&ledger)?;
    let (joint, funding_packet, consuming_packet) = joint.finish(&ledger)?;
    if origin_consuming_packet != Some(funding_packet) {
        return Err(SourceNoteError::InvalidWitness);
    }
    Ok(FiniteValidatedPrefixOriginJoint {
        origin, joint, packets: packets.map(|packet| packet.map(|packet| packet.bytes)),
        funding_packet, consuming_packet, boundary: ledger.tip(),
    })
}

struct TrackedNoteReplay {
    state: TrackedNoteState,
    funding: Option<(SourceNoteOccurrence, usize)>,
    consumption: Option<(SourceNoteOccurrence, usize)>,
}

impl TrackedNoteReplay {
    fn finish(self, ledger: &SproutTestnetLedger)
        -> Result<(FiniteValidatedPrefixNoteFacts, usize, Option<usize>), SourceNoteError>
    {
        let merkle_path = self.state.checked_path(ledger)?;
        let witness = self.state.witness.ok_or(SourceNoteError::FundingNotFound)?;
        let (funding, funding_packet) = self.funding.ok_or(SourceNoteError::InvalidWitness)?;
        if self.state.funding != Some(self.state.selection.funding)
            || self.state.consumption.is_some() != self.consumption.is_some()
        {
            return Err(SourceNoteError::InvalidWitness);
        }
        let anchor = Option::<Anchor>::from(Anchor::from_bytes(ledger.shielded_root(self.state.selection.pool)))
            .ok_or(SourceNoteError::InvalidWitness)?;
        Ok((FiniteValidatedPrefixNoteFacts {
            selection: self.state.selection, funding, merkle_path, anchor,
            tree_count: witness_count(&witness)?, consumption: self.consumption.map(|(occurrence, _)| occurrence),
        }, funding_packet, self.consumption.map(|(_, packet)| packet)))
    }
}

struct ReplayedNotes<const N: usize> {
    notes: [TrackedNoteReplay; N],
    packets: [Option<RetainedPacket>; 3],
    ledger: SproutTestnetLedger,
    boundary_journal: [u8; JOURNAL_LEN],
}

// Only one-note and origin/J callers instantiate this private loop. Each body
// is parsed once for tracking and admitted by the same authoritative validator;
// staging never publishes an occurrence before that admission or the final EOF.
fn replay_notes_testnet<const N: usize>(
    reader: &mut impl Read,
    max_blocks: u32,
    max_input_bytes: u64,
    selections: [SourceNoteSelection; N],
) -> Result<ReplayedNotes<N>, SourceNoteError> {
    let mut notes = selections.map(|selection| TrackedNoteReplay {
        state: TrackedNoteState { selection, witness: None, funding: None, consumption: None },
        funding: None, consumption: None,
    });
    for note in &mut notes { note.state = TrackedNoteState::new(note.state.selection)?; }
    let mut staged = None;
    let mut packets = std::array::from_fn(|_| None);
    let (boundary_journal, ledger) = replay_framed_testnet_with::<SourceNoteError>(
        reader, max_blocks, max_input_bytes, |raw, ledger, phase| {
            match phase {
                ReplayPhase::BeforeBlock => {
                    let height = ledger.tip().height().checked_add(1)
                        .ok_or(SourceReplayError::UnsupportedEra)?;
                    if height >= MAX_BLOCK_COUNT { return Err(SourceReplayError::UnsupportedEra.into()); }
                    if height >= 1_842_420 {
                        let body = PostNu5Block::parse(raw, height)
                            .map_err(|_| SourceReplayError::InvalidTransition)?;
                        // Query mismatch waits for the real complete-body validator.
                        let candidate: Result<_, SourceNoteError> = (|| {
                            let mut next: [Option<TrackedNoteState>; N] = std::array::from_fn(|_| None);
                            let mut locators = [None; 4];
                            for (index, note) in notes.iter().enumerate() {
                                next[index] = note.state.stage(ledger, body.transactions(), height)?;
                                if let Some(state) = &next[index] {
                                    locators[2 * index] = state.funding.filter(|_| note.state.funding.is_none());
                                    locators[2 * index + 1] = state.consumption.filter(|_| note.state.consumption.is_none());
                                }
                            }
                            if N == 2 {
                                check_origin_joint_link(next[0].as_ref().unwrap_or(&notes[0].state),
                                    next[1].as_ref().unwrap_or(&notes[1].state))?;
                            }
                            Ok((next, transaction_ranges(raw, &body, locators)?))
                        })();
                        staged = Some(candidate);
                    }
                }
                ReplayPhase::Admitted => {
                    if let Some((next, mut ranges)) = staged.take().transpose()? {
                        for (note, state) in notes.iter().zip(&next) {
                            state.as_ref().unwrap_or(&note.state).check_ledger(ledger)?;
                        }
                        for (index, (note, next)) in notes.iter_mut().zip(next).enumerate() {
                            if let Some(next) = next {
                                if note.state.funding.is_none() && let Some(locator) = next.funding {
                                    let packet = retain_shared_packet(&mut packets, raw, locator, ranges[2 * index].take())?;
                                    note.funding = Some((seal_occurrence(locator, ledger.tip())?, packet));
                                }
                                if note.state.consumption.is_none() && let Some(locator) = next.consumption {
                                    let packet = retain_shared_packet(&mut packets, raw, locator, ranges[2 * index + 1].take())?;
                                    note.consumption = Some((seal_occurrence(locator, ledger.tip())?, packet));
                                }
                                note.state = next;
                            }
                        }
                    } else {
                        for note in &notes { note.state.check_ledger(ledger)?; }
                    }
                }
            }
            Ok(())
        },
    )?;
    Ok(ReplayedNotes { notes, packets, ledger, boundary_journal })
}

fn same_transaction(a: SourceFundingLocator, b: SourceFundingLocator) -> bool {
    a.block_height == b.block_height && a.transaction_index == b.transaction_index
        && a.effect_id == b.effect_id && a.auth_digest == b.auth_digest
}

// Mechanically checked linkage only; private derivation/economics live elsewhere.
pub(crate) fn check_origin_joint_link(origin: &TrackedNoteState, joint: &TrackedNoteState) -> Result<(), SourceNoteError> {
    if origin.consumption.is_some_and(|consumption| !same_transaction(consumption, joint.selection.funding))
        || (joint.funding.is_some() && origin.consumption.is_none())
    {
        return Err(SourceNoteError::FundingMismatch);
    }
    Ok(())
}

struct RetainedPacket {
    locator: SourceFundingLocator,
    bytes: Zeroizing<Vec<u8>>,
}

fn retain_shared_packet(
    packets: &mut [Option<RetainedPacket>; 3],
    raw: &[u8],
    locator: SourceFundingLocator,
    range: Option<Range<usize>>,
) -> Result<usize, SourceNoteError> {
    if let Some(index) = packets.iter().position(|packet|
        packet.as_ref().is_some_and(|packet| same_transaction(packet.locator, locator)))
    {
        let bytes = raw.get(range.ok_or(SourceNoteError::InvalidWitness)?).ok_or(SourceNoteError::InvalidWitness)?;
        if packets[index].as_ref().ok_or(SourceNoteError::InvalidWitness)?.bytes.as_slice() != bytes {
            return Err(SourceNoteError::InvalidWitness);
        }
        return Ok(index);
    }
    let index = packets.iter().position(Option::is_none).ok_or(SourceNoteError::InvalidWitness)?;
    packets[index] = Some(RetainedPacket { locator, bytes: retain_packet(raw, range)? });
    Ok(index)
}

fn seal_occurrence(locator: SourceFundingLocator, block: HeaderTip) -> Result<SourceNoteOccurrence, SourceNoteError> {
    if locator.block_height != block.height() { return Err(SourceNoteError::InvalidWitness); }
    Ok(SourceNoteOccurrence { block, locator })
}

// Check both occurrence identities before reusing the shared canonical span
// extractor over this SAME complete parsed body; no second parse or replay.
pub(crate) fn transaction_ranges<const N: usize>(
    raw: &[u8],
    body: &PostNu5Block<'_>,
    locators: [Option<SourceFundingLocator>; N],
) -> Result<[Option<Range<usize>>; N], SourceNoteError> {
    for locator in locators.iter().flatten() {
        let transaction = body.transactions().get(locator.transaction_index as usize)
            .ok_or(SourceNoteError::InvalidWitness)?;
        if transaction.effect_id() != locator.effect_id
            || transaction.auth_digest() != Some(locator.auth_digest)
        {
            return Err(SourceNoteError::InvalidWitness);
        }
    }
    post_nu5_transaction_ranges(raw, body, locators.map(|locator| locator.map(|locator| locator.transaction_index as usize)))
        .map_err(|_| SourceNoteError::InvalidWitness)
}

fn retain_packet(raw: &[u8], range: Option<Range<usize>>) -> Result<Zeroizing<Vec<u8>>, SourceNoteError> {
    let bytes = raw.get(range.ok_or(SourceNoteError::InvalidWitness)?)
        .filter(|bytes| !bytes.is_empty() && bytes.len() <= MAX_BLOCK_BYTES)
        .ok_or(SourceNoteError::InvalidWitness)?;
    let mut packet = Zeroizing::new(Vec::with_capacity(bytes.len()));
    packet.extend_from_slice(bytes);
    Ok(packet)
}

// Unsealed mechanics can be inspected by existing isolated ledger tests, but
// cannot construct an authenticated occurrence or a public terminal note fact.
#[derive(Clone)]
pub(crate) struct TrackedNoteState {
    selection: SourceNoteSelection,
    pub(crate) witness: Option<IncrementalWitness<MerkleHashOrchard, 32>>,
    pub(crate) funding: Option<SourceFundingLocator>,
    pub(crate) consumption: Option<SourceFundingLocator>,
}

impl TrackedNoteState {
    pub(crate) fn new(selection: SourceNoteSelection) -> Result<Self, SourceNoteError> {
        let height = selection.funding.block_height;
        let activation = match selection.pool {
            ShieldedPool::Orchard => 1_842_420,
            ShieldedPool::Ironwood => 4_134_000,
            ShieldedPool::Sprout | ShieldedPool::Sapling => return Err(SourceNoteError::InvalidSelection),
        };
        if !(activation..MAX_BLOCK_COUNT).contains(&height)
            || (selection.pool == ShieldedPool::Orchard && (4_048_500..4_052_000).contains(&height))
            || usize::try_from(selection.funding.transaction_index).map_or(true, |index| index >= MAX_BLOCK_BYTES / 25)
            || usize::try_from(selection.funding.action_index).map_or(true, |index| index >= MAX_BLOCK_BYTES / 820)
            || Option::<ExtractedNoteCommitment>::from(ExtractedNoteCommitment::from_bytes(&selection.commitment)).is_none()
            || Option::<Nullifier>::from(Nullifier::from_bytes(&selection.nullifier)).is_none()
        {
            return Err(SourceNoteError::InvalidSelection);
        }
        Ok(Self { selection, witness: None, funding: None, consumption: None })
    }

    pub(crate) fn stage(
        &self,
        parent: &SproutTestnetLedger,
        transactions: &[PostNu5Transaction<'_>],
        height: u32,
    ) -> Result<Option<Self>, SourceNoteError> {
        self.check_ledger(parent)?;
        let funding_block = height == self.selection.funding.block_height;
        if self.funding.is_none() && height > self.selection.funding.block_height {
            return Err(SourceNoteError::FundingMismatch);
        }
        let touches_pool = transactions.iter().any(|transaction| match transaction {
            PostNu5Transaction::V5(raw) => self.selection.pool == ShieldedPool::Orchard && raw.orchard().is_some(),
            PostNu5Transaction::V6(transaction) => match self.selection.pool {
                ShieldedPool::Orchard => transaction.orchard_bundle().is_some(),
                ShieldedPool::Ironwood => transaction.ironwood_bundle().is_some(),
                _ => false,
            },
            PostNu5Transaction::V4(_) => false,
        });
        if !touches_pool && !funding_block { return Ok(None); }
        if funding_block {
            let transaction = transactions.get(self.selection.funding.transaction_index as usize)
                .ok_or(SourceNoteError::FundingMismatch)?;
            if transaction.effect_id() != self.selection.funding.effect_id
                || transaction.auth_digest() != Some(self.selection.funding.auth_digest)
            {
                return Err(SourceNoteError::FundingMismatch);
            }
        }
        // Clone only the bounded selected witness, never the ledger/history tree.
        let mut staged = self.clone();
        // Exactly one depth-bounded parent-frontier conversion, only at funding.
        let mut tree = if funding_block {
            Some(CommitmentTree::from_frontier(parent.orchard_family_frontier(self.selection.pool)
                .ok_or(SourceNoteError::InvalidSelection)?))
        } else { None };
        for (transaction_index, transaction) in transactions.iter().enumerate() {
            for_pool_actions(transaction, self.selection.pool, |action_index, node, nullifier| {
                let locator = || -> Result<SourceFundingLocator, SourceNoteError> {
                    Ok(SourceFundingLocator {
                        block_height: height,
                        transaction_index: u32::try_from(transaction_index).map_err(|_| SourceNoteError::InvalidWitness)?,
                        action_index: u32::try_from(action_index).map_err(|_| SourceNoteError::InvalidWitness)?,
                        effect_id: transaction.effect_id(),
                        auth_digest: transaction.auth_digest().ok_or(SourceNoteError::InvalidWitness)?,
                    })
                };
                if nullifier == self.selection.nullifier {
                    if staged.funding.is_none() { return Err(SourceNoteError::NullifierBeforeFunding); }
                    if staged.consumption.is_some() { return Err(SourceNoteError::InvalidWitness); }
                    staged.consumption = Some(locator()?);
                }
                if staged.witness.is_none() && tree.is_none() { return Ok(()); }
                if let Some(witness) = staged.witness.as_mut() {
                    witness.append(node).map_err(|_| SourceNoteError::InvalidWitness)?;
                } else if let Some(tree) = tree.as_mut() {
                    tree.append(node).map_err(|_| SourceNoteError::InvalidWitness)?;
                }
                if funding_block
                    && transaction_index == self.selection.funding.transaction_index as usize
                    && action_index == self.selection.funding.action_index as usize
                {
                    if node.to_bytes() != self.selection.commitment || staged.funding.is_some() {
                        return Err(SourceNoteError::FundingMismatch);
                    }
                    // The selected leaf was appended above, never append it twice.
                    staged.witness = IncrementalWitness::from_tree(tree.take().ok_or(SourceNoteError::InvalidWitness)?);
                    if staged.witness.is_none() { return Err(SourceNoteError::InvalidWitness); }
                    staged.funding = Some(locator()?);
                }
                Ok(())
            })?;
        }
        if funding_block && staged.funding.is_none() { return Err(SourceNoteError::FundingMismatch); }
        Ok(Some(staged))
    }

    pub(crate) fn check_ledger(&self, ledger: &SproutTestnetLedger) -> Result<(), SourceNoteError> {
        let frontier = ledger.orchard_family_frontier(self.selection.pool)
            .ok_or(SourceNoteError::InvalidSelection)?;
        if let Some(witness) = &self.witness {
            // Check the actual COMMITTED frontier count: root-equal PushAnchor
            // may retain a parent frontier rather than install a candidate one.
            if witness.root().to_bytes() != ledger.shielded_root(self.selection.pool)
                || witness_count(witness)? != frontier.tree_size()
                || self.funding != Some(self.selection.funding)
            {
                return Err(SourceNoteError::InvalidWitness);
            }
        } else if self.funding.is_some() || self.consumption.is_some() {
            return Err(SourceNoteError::InvalidWitness);
        }
        if ledger.contains_nullifier(self.selection.pool, &self.selection.nullifier) != self.consumption.is_some() {
            return Err(if self.funding.is_none() { SourceNoteError::NullifierBeforeFunding } else { SourceNoteError::InvalidWitness });
        }
        Ok(())
    }

    pub(crate) fn checked_path(&self, ledger: &SproutTestnetLedger) -> Result<MerklePath, SourceNoteError> {
        self.check_ledger(ledger)?;
        let witness = self.witness.as_ref().ok_or(SourceNoteError::FundingNotFound)?;
        let commitment = Option::<ExtractedNoteCommitment>::from(ExtractedNoteCommitment::from_bytes(&self.selection.commitment))
            .ok_or(SourceNoteError::InvalidSelection)?;
        let path: MerklePath = witness.path().ok_or(SourceNoteError::InvalidWitness)?.into();
        if u64::from(path.position()) != u64::from(witness.witnessed_position())
            || path.root(commitment).to_bytes() != ledger.shielded_root(self.selection.pool)
        {
            return Err(SourceNoteError::InvalidWitness);
        }
        Ok(path)
    }
}

fn witness_count(witness: &IncrementalWitness<MerkleHashOrchard, 32>) -> Result<u64, SourceNoteError> {
    u64::from(witness.tip_position()).checked_add(1).ok_or(SourceNoteError::InvalidWitness)
}

// The validator's original V5 action bytes and actual typed V6 pool slots remain
// authoritative. Every disabled/dummy/padding action participates in this order.
fn for_pool_actions(
    transaction: &PostNu5Transaction<'_>,
    pool: ShieldedPool,
    mut action: impl FnMut(usize, MerkleHashOrchard, [u8; 32]) -> Result<(), SourceNoteError>,
) -> Result<(), SourceNoteError> {
    match transaction {
        PostNu5Transaction::V5(raw) if pool == ShieldedPool::Orchard => {
            if let Some(bundle) = raw.orchard() {
                for (index, bytes) in bundle.actions().as_chunks::<820>().0.iter().enumerate() {
                    let commitment = bytes[96..128].try_into().expect("parsed original cmx");
                    let node = Option::<MerkleHashOrchard>::from(MerkleHashOrchard::from_bytes(&commitment))
                        .ok_or(SourceReplayError::InvalidTransition)?;
                    action(index, node, bytes[32..64].try_into().expect("parsed original nullifier"))?;
                }
            }
        }
        PostNu5Transaction::V6(transaction) => {
            let bundle = match pool {
                ShieldedPool::Orchard => transaction.orchard_bundle(),
                ShieldedPool::Ironwood => transaction.ironwood_bundle(),
                _ => None,
            };
            if let Some(bundle) = bundle {
                for (index, item) in bundle.actions().iter().enumerate() {
                    action(index, MerkleHashOrchard::from_cmx(item.cmx()), item.nullifier().to_bytes())?;
                }
            }
        }
        _ => {}
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn isolated_origin_joint_packet_retention_shares_f_without_losing_exact_bytes() {
        // Structural retention only, not connected or authenticated source evidence.
        let raw = include_bytes!("../tests/fixtures/testnet-nu5-block-1842467.bin");
        let body = PostNu5Block::parse(raw, 1_842_467).unwrap();
        let transaction = &body.transactions()[1];
        let locator = SourceFundingLocator {
            block_height: 1_842_467, transaction_index: 1, action_index: 0,
            effect_id: transaction.effect_id(), auth_digest: transaction.auth_digest().unwrap(),
        };
        let [Some(range), None] = transaction_ranges(raw, &body, [Some(locator), None]).unwrap()
            else { panic!("original transaction span missing"); };
        let mut packets = std::array::from_fn(|_| None);
        let funding = retain_shared_packet(&mut packets, raw, locator, Some(range.clone())).unwrap();
        let shared = retain_shared_packet(&mut packets, raw,
            SourceFundingLocator { action_index: 1, ..locator }, Some(range.clone())).unwrap();
        assert_eq!(shared, funding);
        assert_eq!(packets.iter().flatten().count(), 1);
        assert_eq!(packets[funding].as_ref().unwrap().bytes.as_slice(),
            include_bytes!("../tests/fixtures/orchard-pure-testnet-1842467.bin"));
        let mut changed = raw.to_vec();
        changed[range.start] ^= 1;
        assert_eq!(retain_shared_packet(&mut packets, &changed, locator, Some(range.clone())),
            Err(SourceNoteError::InvalidWitness));
        for transaction_index in [2, 3] {
            retain_shared_packet(&mut packets, raw,
                SourceFundingLocator { transaction_index, ..locator }, Some(range.clone())).unwrap();
        }
        assert_eq!(packets.iter().flatten().count(), 3);
        assert_eq!(retain_shared_packet(&mut packets, raw,
            SourceFundingLocator { transaction_index: 4, ..locator }, Some(range)),
            Err(SourceNoteError::InvalidWitness));
    }

    fn origin_joint_selections() -> [SourceNoteSelection; 2] {
        [1, 2].map(|transaction_index| SourceNoteSelection {
            pool: ShieldedPool::Ironwood, commitment: [0; 32], nullifier: [0; 32],
            funding: SourceFundingLocator {
                block_height: 4_134_000, transaction_index, action_index: 0,
                effect_id: [0; 32], auth_digest: [0; 32],
            },
        })
    }

    fn connected_early_history() -> Vec<u8> {
        let blocks: [&[u8]; 11] = [
            include_bytes!("../tests/fixtures/testnet-genesis.bin"),
            include_bytes!("../tests/fixtures/testnet-block-1.bin"),
            include_bytes!("../tests/fixtures/testnet-block-2.bin"),
            include_bytes!("../tests/fixtures/testnet-block-3.bin"),
            include_bytes!("../tests/fixtures/testnet-block-4.bin"),
            include_bytes!("../tests/fixtures/testnet-block-5.bin"),
            include_bytes!("../tests/fixtures/testnet-block-6.bin"),
            include_bytes!("../tests/fixtures/testnet-block-7.bin"),
            include_bytes!("../tests/fixtures/testnet-block-8.bin"),
            include_bytes!("../tests/fixtures/testnet-block-9.bin"),
            include_bytes!("../tests/fixtures/testnet-block-10.bin"),
        ];
        let mut framed = 11u32.to_le_bytes().to_vec();
        for block in blocks {
            framed.extend_from_slice(&u32::try_from(block.len()).unwrap().to_le_bytes());
            framed.extend_from_slice(block);
        }
        framed
    }

    #[test]
    fn origin_joint_connected_genesis_absence_waits_for_every_body_and_eof() {
        let input = connected_early_history();
        assert_eq!(input.len(), 17_920);
        let [origin, joint] = origin_joint_selections();
        let mut reader = input.as_slice();
        assert_eq!(
            replay_origin_joint_testnet(&mut reader, 11, 17_920, origin, joint).unwrap_err(),
            SourceNoteError::FundingNotFound,
        );
        assert!(reader.is_empty());
        let mut corrupt = input.clone();
        let last = include_bytes!("../tests/fixtures/testnet-block-10.bin");
        let offset = input.len() - last.len();
        corrupt[offset + 1488 + 50] ^= 1;
        assert_eq!(
            replay_origin_joint_testnet(&mut corrupt.as_slice(), 11, 17_920, origin, joint).unwrap_err(),
            SourceNoteError::Replay(SourceReplayError::InvalidTransition),
        );
        assert_eq!(
            replay_origin_joint_testnet(&mut &input[..input.len() - 1], 11, 17_920, origin, joint).unwrap_err(),
            SourceNoteError::Replay(SourceReplayError::InvalidFraming),
        );
        let mut suffix = input.clone();
        suffix.push(0);
        assert_eq!(
            replay_origin_joint_testnet(&mut suffix.as_slice(), 11, 17_920, origin, joint).unwrap_err(),
            SourceNoteError::Replay(SourceReplayError::TrailingBytes),
        );
        let genesis = include_bytes!("../tests/fixtures/testnet-genesis.bin");
        let mut missing_genesis = 1u32.to_le_bytes().to_vec();
        missing_genesis.extend_from_slice(&1692u32.to_le_bytes());
        missing_genesis.extend_from_slice(&[0; 1692]);
        assert_eq!(
            replay_origin_joint_testnet(&mut missing_genesis.as_slice(), 1, 1700, origin, joint).unwrap_err(),
            SourceNoteError::Replay(SourceReplayError::InvalidGenesis),
        );
        let late = include_bytes!("../tests/fixtures/testnet-nu5-block-1842467.bin");
        let mut isolated = 2u32.to_le_bytes().to_vec();
        for block in [genesis.as_slice(), late.as_slice()] {
            isolated.extend_from_slice(&u32::try_from(block.len()).unwrap().to_le_bytes());
            isolated.extend_from_slice(block);
        }
        assert_eq!(
            replay_origin_joint_testnet(&mut isolated.as_slice(), 2, isolated.len() as u64, origin, joint).unwrap_err(),
            SourceNoteError::Replay(SourceReplayError::InvalidTransition),
        );
    }

    #[test]
    fn origin_joint_eof_failure_cannot_publish_origin_or_joint_absence() {
        struct FailingEof<'a>(&'a [u8]);
        impl Read for FailingEof<'_> {
            fn read(&mut self, output: &mut [u8]) -> std::io::Result<usize> {
                if self.0.is_empty() { return Err(std::io::Error::other("private-origin-eof")); }
                self.0.read(output)
            }
        }
        let input = connected_early_history();
        let [origin, joint] = origin_joint_selections();
        let mut reader = FailingEof(&input);
        let error = replay_origin_joint_testnet(&mut reader, 11, 17_920, origin, joint).unwrap_err();
        assert_eq!(error, SourceNoteError::Replay(SourceReplayError::InputUnavailable));
        assert!(reader.0.is_empty());
        assert!(!error.to_string().contains("private-origin-eof"));
    }

    #[test]
    fn origin_joint_requires_an_earlier_origin_transaction_not_an_earlier_action() {
        struct Unread;
        impl Read for Unread {
            fn read(&mut self, _: &mut [u8]) -> std::io::Result<usize> {
                panic!("invalid origin/joint selection must not read history")
            }
        }
        let [origin, joint] = origin_joint_selections();
        for funding in [
            SourceFundingLocator { action_index: 1, ..origin.funding },
            SourceFundingLocator { transaction_index: 0, ..joint.funding },
            SourceFundingLocator { block_height: origin.funding.block_height - 1, ..joint.funding },
        ] {
            assert_eq!(
                replay_origin_joint_testnet(&mut Unread, 11, 17_920, origin,
                    SourceNoteSelection { funding, ..joint }).unwrap_err(),
                SourceNoteError::InvalidSelection,
            );
        }
    }

    #[test]
    fn isolated_original_v5_packet_retains_exact_bytes_and_both_identity_bindings() {
        // Structural extraction ONLY, not connected history or public evidence.
        let mut raw = include_bytes!("../tests/fixtures/testnet-nu5-block-1842467.bin").to_vec();
        let original = include_bytes!("../tests/fixtures/orchard-pure-testnet-1842467.bin");
        let body = PostNu5Block::parse(&raw, 1_842_467).unwrap();
        let transaction = &body.transactions()[1];
        let locator = SourceFundingLocator {
            block_height: 1_842_467, transaction_index: 1, action_index: 0,
            effect_id: transaction.effect_id(), auth_digest: transaction.auth_digest().unwrap(),
        };
        let [funding, consumption] = transaction_ranges(&raw, &body, [Some(locator), Some(locator)]).unwrap();
        let funding = retain_packet(&raw, funding).unwrap();
        let consumption = retain_packet(&raw, consumption).unwrap();
        assert_eq!(funding.as_slice(), original);
        assert_eq!(consumption.as_slice(), original);
        for identity in 0..2 {
            let mut wrong = locator;
            if identity == 0 { wrong.effect_id[0] ^= 1; } else { wrong.auth_digest[0] ^= 1; }
            assert_eq!(transaction_ranges(&raw, &body, [Some(wrong), None]).unwrap_err(), SourceNoteError::InvalidWitness);
        }
        assert_eq!(transaction_ranges(&raw, &body, [None, None]).unwrap(), [None, None]);
        assert_eq!(retain_packet(&raw, Some(0..0)).unwrap_err(), SourceNoteError::InvalidWitness);
        assert_eq!(retain_packet(&raw, Some(0..raw.len() + 1)).unwrap_err(), SourceNoteError::InvalidWitness);
        drop(body);
        raw.fill(0);
        assert_eq!(funding.as_slice(), original);
        assert_eq!(consumption.as_slice(), original);
    }
}
