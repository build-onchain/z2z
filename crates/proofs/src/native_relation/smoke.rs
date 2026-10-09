//! Private synthetic-consumer harness, not a financial wire ABI or origin proof.
//! Full actual F and one independently specified C/R consumer are checked by the
//! production core, including their genuine authorization. No trusted journals.
use super::{
    FundingFacts, JointSpendFacts, NativeOutputFacts, NativeRelationError as Error,
    OwnedInputFacts, SourceFacts, MAX_ACTIONS, MAX_PCZT_BYTES,
};
use orchard::{
    Address, Anchor, Note, keys::FullViewingKey,
    note::{NoteVersion, RandomSeed, Rho}, tree::{MerkleHashOrchard, MerklePath}, value::NoteValue,
};
use zcash_primitives::transaction::fees::zip317;
use zcash_protocol::{consensus::{BranchId, Network}, constants::MAX_BLOCK_BYTES, value::Zatoshis};
use zeroize::Zeroizing;

const MAX_FRAME: usize = 2 * MAX_PCZT_BYTES + 2 * MAX_BLOCK_BYTES + MAX_ACTIONS * 575 + 2048;
pub const SUCCESS: &[u8] = b"native-relation-private-smoke-passed";

struct Reader<'a>(&'a [u8]);
impl<'a> Reader<'a> {
    fn bytes(&mut self, count: usize) -> Result<&'a [u8], Error> {
        let (value, rest) = self.0.split_at_checked(count).ok_or(Error::InvalidPczt)?;
        self.0 = rest;
        Ok(value)
    }
    fn array<const N: usize>(&mut self) -> Result<[u8; N], Error> {
        self.bytes(N)?.try_into().map_err(|_| Error::InvalidPczt)
    }
    fn u32(&mut self) -> Result<u32, Error> { Ok(u32::from_le_bytes(self.array()?)) }
    fn u64(&mut self) -> Result<u64, Error> { Ok(u64::from_le_bytes(self.array()?)) }
    fn blob(&mut self, max: usize) -> Result<&'a [u8], Error> {
        let len = self.u32()? as usize;
        if len == 0 || len > max { return Err(Error::InvalidPczt); }
        self.bytes(len)
    }
    fn address(&mut self) -> Result<Address, Error> {
        Address::from_raw_address_bytes(&self.array()?).into_option().ok_or(Error::OutputMismatch)
    }
    fn fvk(&mut self) -> Result<FullViewingKey, Error> {
        let bytes = Zeroizing::new(self.array()?);
        FullViewingKey::from_bytes(&bytes).ok_or(Error::InputNotOwned)
    }
    fn note(&mut self) -> Result<Note, Error> {
        let recipient = self.address()?;
        let value = self.u64()?;
        Zatoshis::from_u64(value).map_err(|_| Error::AmountOutOfRange)?;
        let rho = Rho::from_bytes(&self.array()?).into_option().ok_or(Error::InputMismatch)?;
        let seed = Zeroizing::new(self.array()?);
        let seed = RandomSeed::from_bytes(*seed, &rho).into_option().ok_or(Error::InputMismatch)?;
        Note::from_parts(recipient, NoteValue::from_raw(value), rho, seed, NoteVersion::V3)
            .into_option().ok_or(Error::InputMismatch)
    }
    fn source(&mut self) -> Result<(u32, u32, zip317::FeeRule), Error> {
        let target = self.u32()?;
        let expiry = self.u32()?;
        let marginal_fee = Zatoshis::from_u64(self.u64()?).map_err(|_| Error::FeeMismatch)?;
        let grace_actions = self.u32()? as usize;
        let input_size = self.u32()? as usize;
        let output_size = self.u32()? as usize;
        let rule = zip317::FeeRule::non_standard(marginal_fee, grace_actions, input_size, output_size)
            .ok_or(Error::FeeMismatch)?;
        Ok((target, expiry, rule))
    }
}
fn source<'a>(parts: &'a (u32, u32, zip317::FeeRule)) -> SourceFacts<'a> {
    SourceFacts { network: Network::TestNetwork, target_height: parts.0.into(), expiry_height: parts.1.into(),
        consensus_branch: BranchId::Nu6_3, fee_rule: &parts.2 }
}

/// Same borrowed production checks on native and actual RISC-V; inputs are
/// owner-local bytes, and every output (including requested zero) is explicit.
pub fn verify(input: &[u8]) -> Result<(), Error> {
    if input.is_empty() || input.len() > MAX_FRAME { return Err(Error::InvalidPczt); }
    let mut reader = Reader(input);
    let funding_source = reader.source()?;
    let input_note = reader.note()?;
    let input_fvk = reader.fvk()?;
    let position = reader.u32()?;
    let mut sibling_bytes = Zeroizing::new([[0; 32]; 32]);
    for sibling in &mut *sibling_bytes { *sibling = reader.array()?; }
    let mut siblings = [MerkleHashOrchard::from_bytes(&[0; 32]).unwrap(); 32];
    for (sibling, bytes) in siblings.iter_mut().zip(sibling_bytes.iter()) {
        *sibling = MerkleHashOrchard::from_bytes(bytes).into_option().ok_or(Error::AnchorMismatch)?;
    }
    let path = MerklePath::from_parts(position, siblings);
    let input_anchor = Anchor::from_bytes(reader.array()?)
        .into_option().ok_or(Error::AnchorMismatch)?;
    let joint_fvk = reader.fvk()?;
    let group_ak = reader.array()?;
    let joint_requested_index = reader.u32()? as usize;
    let fee_f = reader.u64()?;
    let count = reader.u32()? as usize;
    if count == 0 || count > MAX_ACTIONS || count > reader.0.len() / 567 { return Err(Error::InvalidOutputIndex); }
    let mut actions = Vec::with_capacity(count);
    let mut outputs = Vec::with_capacity(count);
    for _ in 0..count {
        actions.push(reader.u32()? as usize);
        let recipient = reader.address()?;
        let value = reader.u64()?;
        let memo: &[u8; 512] = reader.bytes(512)?.try_into().map_err(|_| Error::CiphertextMismatch)?;
        outputs.push(NativeOutputFacts { recipient, value, memo: Some(memo) });
    }
    let consumer_source = reader.source()?;
    let consumer_recipient = reader.address()?;
    let consumer_value = reader.u64()?;
    let consumer_memo: &[u8; 512] = reader.bytes(512)?.try_into().map_err(|_| Error::CiphertextMismatch)?;
    let fee_consumer = reader.u64()?;
    let consumer_anchor = Anchor::from_bytes(reader.array()?).into_option().ok_or(Error::AnchorMismatch)?;
    let private_f = reader.blob(MAX_PCZT_BYTES)?;
    let raw_f = reader.blob(MAX_BLOCK_BYTES)?;
    let private_consumer = reader.blob(MAX_PCZT_BYTES)?;
    let raw_consumer = reader.blob(MAX_BLOCK_BYTES)?;
    if !reader.0.is_empty() { return Err(Error::NonCanonicalEncoding); }
    let transaction_f = super::parse_transaction(raw_f)?;
    let funding = FundingFacts {
        source: source(&funding_source), input: OwnedInputFacts { note: &input_note, full_viewing_key: &input_fvk,
            merkle_path: &path, anchor: input_anchor },
        private_pczt: private_f, requested_output_actions: &actions, joint_requested_index,
        joint_full_viewing_key: &joint_fvk, group_ak, fee: fee_f,
    };
    let checked_f = super::verify_funding(&funding, outputs.into_iter(), Some(&transaction_f))?;
    let consumer = JointSpendFacts {
        source: source(&consumer_source), note: &checked_f.joint_note, full_viewing_key: &joint_fvk,
        group_ak, payout: NativeOutputFacts { recipient: consumer_recipient, value: consumer_value,
            memo: Some(consumer_memo) }, fee: fee_consumer,
    };
    let transaction_consumer = super::parse_transaction(raw_consumer)?;
    super::verify_joint_consumer(private_consumer, &consumer, consumer_anchor, &transaction_consumer)?;
    Ok(())
}

#[cfg(not(target_os = "zkvm"))]
fn encode_source(bytes: &mut Vec<u8>, source: &SourceFacts<'_>) -> Result<(), Error> {
    if source.network != Network::TestNetwork || source.consensus_branch != BranchId::Nu6_3 {
        return Err(Error::UnsupportedProfile);
    }
    bytes.extend_from_slice(&u32::from(source.target_height).to_le_bytes());
    bytes.extend_from_slice(&u32::from(source.expiry_height).to_le_bytes());
    bytes.extend_from_slice(&u64::from(source.fee_rule.marginal_fee()).to_le_bytes());
    for value in [source.fee_rule.grace_actions(), source.fee_rule.p2pkh_standard_input_size(),
        source.fee_rule.p2pkh_standard_output_size()] {
        bytes.extend_from_slice(&u32::try_from(value).map_err(|_| Error::FeeMismatch)?.to_le_bytes());
    }
    Ok(())
}

/// Witness producer used only for generated local fixtures. Preallocates the
/// complete private frame before writing secrets; no growth frees unwiped bytes.
#[cfg(not(target_os = "zkvm"))]
#[allow(clippy::too_many_arguments)]
pub fn encode<'a>(
    funding: &FundingFacts<'_>, outputs: impl ExactSizeIterator<Item = NativeOutputFacts<'a>>,
    raw_f: &[u8], private_consumer: &[u8], consumer: &JointSpendFacts<'_>,
    consumer_anchor: Anchor, raw_consumer: &[u8],
) -> Result<Zeroizing<Vec<u8>>, Error> {
    let count = outputs.len();
    if count == 0 || count > MAX_ACTIONS || count != funding.requested_output_actions.len() { return Err(Error::InvalidOutputIndex); }
    for (blob, max) in [(funding.private_pczt, MAX_PCZT_BYTES), (raw_f, MAX_BLOCK_BYTES),
        (private_consumer, MAX_PCZT_BYTES), (raw_consumer, MAX_BLOCK_BYTES)] {
        if blob.is_empty() || blob.len() > max { return Err(Error::InvalidPczt); }
    }
    let capacity = 2090 + 567 * count + funding.private_pczt.len() + raw_f.len() + private_consumer.len() + raw_consumer.len();
    if capacity > MAX_FRAME { return Err(Error::InvalidPczt); }
    let mut bytes = Zeroizing::new(Vec::with_capacity(capacity));
    encode_source(&mut bytes, &funding.source)?;
    let note = funding.input.note;
    bytes.extend_from_slice(&note.recipient().to_raw_address_bytes());
    bytes.extend_from_slice(&note.value().inner().to_le_bytes());
    bytes.extend_from_slice(&note.rho().to_bytes());
    bytes.extend_from_slice(note.rseed().as_bytes());
    bytes.extend_from_slice(&*Zeroizing::new(funding.input.full_viewing_key.to_bytes()));
    bytes.extend_from_slice(&funding.input.merkle_path.position().to_le_bytes());
    for sibling in funding.input.merkle_path.auth_path() { bytes.extend_from_slice(&sibling.to_bytes()); }
    bytes.extend_from_slice(&funding.input.anchor.to_bytes());
    bytes.extend_from_slice(&*Zeroizing::new(funding.joint_full_viewing_key.to_bytes()));
    bytes.extend_from_slice(&funding.group_ak);
    bytes.extend_from_slice(&u32::try_from(funding.joint_requested_index).map_err(|_| Error::InvalidOutputIndex)?.to_le_bytes());
    bytes.extend_from_slice(&funding.fee.to_le_bytes());
    bytes.extend_from_slice(&(count as u32).to_le_bytes());
    for (&action, output) in funding.requested_output_actions.iter().zip(outputs) {
        bytes.extend_from_slice(&u32::try_from(action).map_err(|_| Error::InvalidOutputIndex)?.to_le_bytes());
        bytes.extend_from_slice(&output.recipient.to_raw_address_bytes());
        bytes.extend_from_slice(&output.value.to_le_bytes());
        bytes.extend_from_slice(output.memo.ok_or(Error::MissingMetadata)?);
    }
    encode_source(&mut bytes, &consumer.source)?;
    bytes.extend_from_slice(&consumer.payout.recipient.to_raw_address_bytes());
    bytes.extend_from_slice(&consumer.payout.value.to_le_bytes());
    bytes.extend_from_slice(consumer.payout.memo.ok_or(Error::MissingMetadata)?);
    bytes.extend_from_slice(&consumer.fee.to_le_bytes());
    bytes.extend_from_slice(&consumer_anchor.to_bytes());
    for blob in [funding.private_pczt, raw_f, private_consumer, raw_consumer] {
        bytes.extend_from_slice(&(blob.len() as u32).to_le_bytes());
        bytes.extend_from_slice(blob);
    }
    if bytes.len() > MAX_FRAME { return Err(Error::InvalidPczt); }
    Ok(bytes)
}
