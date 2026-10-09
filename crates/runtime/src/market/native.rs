use super::{Error, Result, config};
use ziquid_zcash::custody::{
    ExpectedNativeEffects, ExpectedNativeOutput, NativeOutputKind, ReservedNativeInput,
    UnsignedNativeInspection,
};
use crate::market::ledger::NativePlan;
use ziquid_protocol::market::{Domain, Id, ObservationEnvironment, Operation, SourceOccurrence};
use orchard::{Address, keys::FullViewingKey};
use serde::Deserialize;
use serde_json::{Value, json};
use std::path::Path;

const MAX_PCZT_BYTES: usize = 16 * 1024 * 1024;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NativePolicy {
    pub domain_canonical: Vec<u8>,
    pub environment: String,
    pub lock_time: u32,
    pub expiry_height: u32,
    pub fee: u64,
    pub inputs: Vec<InputPolicy>,
    pub outputs: Vec<OutputPolicy>,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct InputPolicy {
    pub inventory_note: Id,
    #[serde(deserialize_with = "source_occurrence")]
    pub source_occurrence: SourceOccurrence,
    pub note_commitment: Id,
    pub nullifier: Id,
    pub value: u64,
    pub trusted_fvk: Vec<u8>,
}
fn source_occurrence<'de, D: serde::Deserializer<'de>>(
    deserializer: D,
) -> core::result::Result<SourceOccurrence, D::Error> {
    #[derive(Deserialize)]
    #[serde(deny_unknown_fields)]
    struct Coordinates {
        network: u8,
        pool: u8,
        txid: Id,
        action_index: u32,
    }
    let coordinates = Coordinates::deserialize(deserializer)?;
    Ok(SourceOccurrence {
        network: coordinates.network,
        pool: coordinates.pool,
        txid: coordinates.txid,
        action_index: coordinates.action_index,
    })
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OutputPolicy {
    pub recipient: Vec<u8>,
    pub value: u64,
    pub kind: String,
}

pub struct NativeContext {
    pub domain: Domain,
    pub environment: ObservationEnvironment,
    pub lock_time: u32,
    pub expiry_height: u32,
    pub fee: u64,
    pub inputs: Vec<ReservedNativeInput>,
    pub outputs: Vec<ExpectedNativeOutput>,
}
impl NativePolicy {
    pub fn context(self) -> Result<NativeContext> {
        if self.inputs.is_empty()
            || self.inputs.len() > 4096
            || self.outputs.is_empty()
            || self.outputs.len() > 4096
        {
            return Err(Error::Configuration);
        }
        let inputs = self
            .inputs
            .into_iter()
            .map(|input| {
                let fvk: [u8; 96] = input
                    .trusted_fvk
                    .try_into()
                    .map_err(|_| Error::Configuration)?;
                Ok(ReservedNativeInput {
                    inventory_note: input.inventory_note,
                    source_occurrence: input.source_occurrence,
                    note_commitment: input.note_commitment,
                    nullifier: input.nullifier,
                    value: input.value,
                    trusted_fvk: FullViewingKey::from_bytes(&fvk).ok_or(Error::Configuration)?,
                })
            })
            .collect::<Result<Vec<_>>>()?;
        let outputs = self
            .outputs
            .into_iter()
            .map(|output| {
                let raw: [u8; 43] = output
                    .recipient
                    .try_into()
                    .map_err(|_| Error::Configuration)?;
                let kind = match output.kind.as_str() {
                    "Recipient" => NativeOutputKind::Recipient,
                    "Change" => NativeOutputKind::Change,
                    _ => return Err(Error::Configuration),
                };
                Ok(ExpectedNativeOutput {
                    recipient: Address::from_raw_address_bytes(&raw)
                        .into_option()
                        .ok_or(Error::Configuration)?,
                    value: output.value,
                    kind,
                })
            })
            .collect::<Result<Vec<_>>>()?;
        Ok(NativeContext {
            domain: config::domain(&self.domain_canonical)?,
            environment: config::environment(&self.environment)?,
            lock_time: self.lock_time,
            expiry_height: self.expiry_height,
            fee: self.fee,
            inputs,
            outputs,
        })
    }
}
impl NativeContext {
    pub fn expected(&self) -> ExpectedNativeEffects<'_> {
        ExpectedNativeEffects {
            domain: &self.domain,
            lock_time: self.lock_time,
            expiry_height: self.expiry_height,
            fee: self.fee,
            inputs: &self.inputs,
            outputs: &self.outputs,
        }
    }
}

pub fn inspect_file(config_path: &Path, pczt_path: &Path) -> Result<Value> {
    let policy: NativePolicy = config::read(config_path)?;
    let context = policy.context()?;
    let bytes = config::read_bytes(pczt_path, MAX_PCZT_BYTES)?;
    let inspection = ziquid_zcash::custody::inspect_pczt(&bytes, &context.expected())?;
    Ok(summary(&inspection, context.environment))
}

pub fn summary(
    inspection: &UnsignedNativeInspection<'_>,
    environment: ObservationEnvironment,
) -> Value {
    json!({ "status": "effects-checked", "environment": match environment {
        ObservationEnvironment::LocalFixture => "LocalFixture", ObservationEnvironment::Network => "Network" },
        "pczt_digest": hex(inspection.exact_pczt_digest()), "native_txid": hex(inspection.txid()),
        "shielded_sighash": hex(inspection.shielded_sighash()), "fee": inspection.fee(),
        "input_count": inspection.inputs().len(), "output_count": inspection.outputs().len(),
        "lock_time": inspection.lock_time(), "expiry_height": inspection.expiry_height(),
        "signatures_verified": false, "signing_performed": false,
        "proofs_verified": false, "source_history_verified": false, "broadcast": false })
}

/// Exact inspected bytes/effects are necessary but insufficient for handoff.
/// The coordinator must also commit this full NativePlan with three journal ACKs.
pub fn bind_plan(
    operation: &Operation,
    plan: &NativePlan,
    inspection: &UnsignedNativeInspection<'_>,
) -> Result<()> {
    plan.native_intent(*operation)?;
    if operation.domain != *inspection.domain()
        || plan.pczt_digest != *inspection.exact_pczt_digest()
        || plan.transaction != *inspection.txid()
        || plan.sighash != *inspection.shielded_sighash()
        || plan.fee != inspection.fee()
    {
        return Err(Error::NativePlanMismatch);
    }
    let expected_count = plan.inputs.len() + plan.fee_inputs.len();
    if expected_count != inspection.inputs().len()
        || plan
            .inputs
            .iter()
            .chain(&plan.fee_inputs)
            .enumerate()
            .any(|(index, note)| {
                plan.inputs
                    .iter()
                    .chain(&plan.fee_inputs)
                    .take(index)
                    .any(|prior| prior == note)
                    || inspection
                        .inputs()
                        .filter(|input| input.inventory_note() == note)
                        .count()
                        != 1
            })
    {
        return Err(Error::NativePlanMismatch);
    }
    let outputs = inspection.outputs();
    if outputs.len() != plan.change.len() + 1 {
        return Err(Error::NativePlanMismatch);
    }
    let expected_outputs = inspection.expected_outputs();
    if expected_outputs
        .iter()
        .filter(|output| {
            output.kind == NativeOutputKind::Recipient
                && output.recipient.to_raw_address_bytes() == plan.recipient
                && output.value == plan.amount
        })
        .count()
        != 1
        || expected_outputs
            .iter()
            .filter(|output| output.kind == NativeOutputKind::Recipient)
            .count()
            != 1
        || expected_outputs
            .iter()
            .filter(|output| output.kind == NativeOutputKind::Change)
            .count()
            != plan.change.len()
    {
        return Err(Error::NativePlanMismatch);
    }
    for (index, change) in plan.change.iter().enumerate() {
        if plan.change[..index].iter().any(|prior| {
            prior.note == change.note
                || prior.action_index == change.action_index
                || prior.note_commitment == change.note_commitment
                || prior.nullifier == change.nullifier
        }) || !outputs.iter().any(|output| {
            output.recipient().to_raw_address_bytes() == change.receiver
                && output.value() == change.value
                && output.action_index() == change.action_index
                && output.note_commitment() == &change.note_commitment
                && output.nullifier() == Some(&change.nullifier)
        }) || plan
            .change
            .iter()
            .filter(|other| other.receiver == change.receiver && other.value == change.value)
            .count()
            != expected_outputs
                .iter()
                .filter(|expected| {
                    expected.kind == NativeOutputKind::Change
                        && expected.recipient.to_raw_address_bytes() == change.receiver
                        && expected.value == change.value
                })
                .count()
        {
            return Err(Error::NativePlanMismatch);
        }
    }
    if outputs
        .iter()
        .filter(|output| {
            !plan
                .change
                .iter()
                .any(|change| change.action_index == output.action_index())
        })
        .filter(|output| {
            output.recipient().to_raw_address_bytes() == plan.recipient
                && output.value() == plan.amount
        })
        .count()
        != 1
    {
        return Err(Error::NativePlanMismatch);
    }
    Ok(())
}

pub fn hex(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push(DIGITS[(byte >> 4) as usize] as char);
        out.push(DIGITS[(byte & 15) as usize] as char);
    }
    out
}

pub fn unhex(value: &str) -> Result<Vec<u8>> {
    fn nibble(byte: u8) -> Result<u8> {
        match byte {
            b'0'..=b'9' => Ok(byte - b'0'),
            b'a'..=b'f' => Ok(byte - b'a' + 10),
            _ => Err(Error::TargetReceipt),
        }
    }
    if !value.len().is_multiple_of(2) {
        return Err(Error::TargetReceipt);
    }
    value
        .as_bytes()
        .as_chunks::<2>()
        .0
        .iter()
        .map(|pair| Ok((nibble(pair[0])? << 4) | nibble(pair[1])?))
        .collect()
}
