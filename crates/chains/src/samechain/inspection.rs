//! Explicit block-pinned public RPC acquisition, never financial or finality proof.
//!
//! Independently supplied pins are compared with a TRUSTED node's answers. A
//! coherent dishonest node can still lie about code, membership and spentness.
//! No observation here authorizes a payout, certifies a program, or sends funds.

use std::{collections::BTreeMap, error::Error, fmt, time::Duration};
use primitive_types::U256;
use serde::{Deserialize, Deserializer, de::{MapAccess, Visitor, value::MapAccessDeserializer}};
use serde_json::json;
use sha2::{Digest, Sha256};
use tiny_keccak::{Hasher, Keccak};
use url::Url;
use ziquid_protocol::samechain::{
    Deployment, OutputDescriptor, PublicPacket, Role, SingleOwnerPacket, MAX_CIPHERTEXT_BYTES,
    creation::NoteCreationPacket, withdrawal::NoteWithdrawalPacket,
};

use super::UnsignedCall;

const MAX_RESPONSE_BYTES: usize = 1024 * 1024;
const MAX_CODE_BYTES: usize = 24576;
const TREE_CAPACITY: u64 = 1 << 32;
const MAX_EVENTS_PER_KIND: usize = 256;
const MAX_APPENDED_CIPHERTEXT_BYTES: usize = MAX_EVENTS_PER_KIND * MAX_CIPHERTEXT_BYTES;
const EVENT_HEAD_BYTES: usize = 11 * 32;

/// Operational request ceiling only; not measured sufficient gas or a fee limit.
pub const MAX_SIMULATION_GAS: u64 = 30_000_000;

/// Categorical errors deliberately retain no URL, provider text or response bytes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum InspectionError {
    InvalidEndpoint,
    InvalidScope,
    InvalidPacket,
    Transport,
    HttpStatus(u16),
    ResponseTooLarge,
    RpcRejected(i64),
    MalformedResponse,
    WrongChain,
    WrongBlock,
    WrongIdentity,
    WrongState,
}

impl fmt::Display for InspectionError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidEndpoint => f.write_str("invalid inspection endpoint"),
            Self::InvalidScope => f.write_str("invalid inspection scope"),
            Self::InvalidPacket => f.write_str("invalid public inspection packet"),
            Self::Transport => f.write_str("inspection transport unavailable"),
            Self::HttpStatus(status) => write!(f, "inspection HTTP status {status}"),
            Self::ResponseTooLarge => f.write_str("inspection response exceeds limit"),
            Self::RpcRejected(code) => write!(f, "inspection RPC rejected ({code})"),
            Self::MalformedResponse => f.write_str("malformed inspection response"),
            Self::WrongChain => f.write_str("inspection chain mismatch"),
            Self::WrongBlock => f.write_str("inspection block mismatch"),
            Self::WrongIdentity => f.write_str("inspection identity mismatch"),
            Self::WrongState => f.write_str("invalid reported inspection state"),
        }
    }
}
impl Error for InspectionError {}

/// Identity-stage failures remain distinct from execution rejection/unavailability.
/// No variant retains an endpoint, provider message, response bytes or revert data.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SimulationError {
    InvalidCall,
    InvalidGas,
    Inspection(InspectionError),
    RpcRejected(i64),
    MalformedResponse,
}

impl fmt::Display for SimulationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidCall => f.write_str("invalid public simulation call"),
            Self::InvalidGas => f.write_str("invalid simulation gas limit"),
            Self::Inspection(error) => write!(f, "simulation unavailable: {error}"),
            Self::RpcRejected(code) => write!(f, "simulation RPC rejected ({code})"),
            Self::MalformedResponse => f.write_str("malformed simulation response"),
        }
    }
}
impl Error for SimulationError {}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct InspectionScope {
    pub expected: Deployment,
    pub token: [u8; 20],
    pub token_code: [u8; 32],
    pub block_hash: [u8; 32],
    pub policy_id: [u8; 32],
}

impl InspectionScope {
    pub fn validate(&self) -> Result<(), InspectionError> {
        self.expected.validate().map_err(|_| InspectionError::InvalidScope)?;
        if self.token == [0; 20] || self.token_code == [0; 32]
            || self.block_hash == [0; 32] || self.policy_id == [0; 32]
        {
            return Err(InspectionError::InvalidScope);
        }
        Ok(())
    }
}

/// Borrow the existing exact canonical PUBLIC packet, without copying ciphertexts.
#[derive(Clone, Copy)]
pub enum InspectionPacket<'a> {
    Creation(&'a NoteCreationPacket),
    Fill(&'a PublicPacket),
    Single(&'a SingleOwnerPacket),
    Withdrawal(&'a NoteWithdrawalPacket),
}

impl InspectionPacket<'_> {
    /// Native callers can construct malformed public structs without decoding.
    /// Validate the complete variant before inspecting or iterating its outputs.
    pub fn validate(&self) -> Result<(), InspectionError> {
        match self {
            Self::Creation(packet) => packet.validate(),
            Self::Fill(packet) => packet.validate(),
            Self::Single(packet) => packet.validate(),
            Self::Withdrawal(packet) => packet.validate(),
        }.map_err(|_| InspectionError::InvalidPacket)
    }

    fn deployment(&self) -> &Deployment {
        match self {
            Self::Creation(packet) => &packet.deployment,
            Self::Fill(packet) => &packet.deployment,
            Self::Single(packet) => &packet.deployment,
            Self::Withdrawal(packet) => &packet.deployment,
        }
    }

    fn outputs(&self) -> &[OutputDescriptor] {
        match self {
            Self::Creation(packet) => std::slice::from_ref(&packet.output),
            Self::Fill(packet) => &packet.outputs,
            Self::Single(packet) => &packet.outputs,
            Self::Withdrawal(packet) => &packet.outputs,
        }
    }

    fn digest(&self) -> Result<[u8; 32], InspectionError> {
        match self {
            Self::Creation(packet) => packet.digest(),
            Self::Fill(packet) => packet.digest(),
            Self::Single(packet) => packet.digest(),
            Self::Withdrawal(packet) => packet.digest(),
        }.map_err(|_| InspectionError::InvalidPacket)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct InputState {
    pub tree_id: u32,
    pub index: u32,
    pub root: [u8; 32],
    pub nullifier: [u8; 32],
    pub reported_root_count: u64,
    pub reported_spent: bool,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct OutputState {
    pub manifest_index: u32,
    pub commitment: [u8; 32],
    pub reported_seen: bool,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CreationState {
    pub nonce_used: bool,
    pub initial_order_used: Option<bool>,
}

/// Public inclusion positions within one selected block; not receipt/consensus authentication.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct LogOccurrence {
    pub transaction_hash: [u8; 32],
    pub transaction_index: u64,
    pub log_index: u64,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AppendedNote {
    pub occurrence: LogOccurrence,
    pub packet_digest: [u8; 32],
    pub manifest_index: u32,
    pub role: Role,
    pub tree_id: u32,
    pub index: u32,
    pub count: u64,
    pub root: [u8; 32],
    pub commitment: [u8; 32],
    pub recovery_key_commitment: [u8; 32],
    pub ciphertext_version: u16,
    pub ciphertext: Vec<u8>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ConsumedNullifier {
    pub occurrence: LogOccurrence,
    pub packet_digest: [u8; 32],
    pub nullifier: [u8; 32],
}

/// Constructed only by actual acquisition. Appended notes are public recovery observations,
/// not proof, backing, finality, ownership or transfer completion. No deserializer, fake constructor,
/// financial-readiness flag, consensus claim, or raw endpoint/provider text.
#[derive(Debug)]
pub struct AuthorityObservation {
    scope: InspectionScope,
    block_number: U256,
    parent_hash: [u8; 32],
    tree_id: u32,
    tree_count: u64,
    tree_root: [u8; 32],
    input_states: Vec<InputState>,
    output_states: Vec<OutputState>,
    creation: Option<CreationState>,
    response_digests: Vec<[u8; 32]>,
    packet_digest: Option<[u8; 32]>,
    appended_notes: Vec<AppendedNote>,
    consumed_nullifiers: Vec<ConsumedNullifier>,
}

impl AuthorityObservation {
    pub fn deployment(&self) -> &Deployment { &self.scope.expected }
    pub fn token(&self) -> [u8; 20] { self.scope.token }
    pub fn token_code(&self) -> [u8; 32] { self.scope.token_code }
    pub fn block_hash(&self) -> [u8; 32] { self.scope.block_hash }
    pub fn block_number(&self) -> U256 { self.block_number }
    pub fn parent_hash(&self) -> [u8; 32] { self.parent_hash }
    pub fn policy_id(&self) -> [u8; 32] { self.scope.policy_id }
    pub fn tree_id(&self) -> u32 { self.tree_id }
    pub fn tree_count(&self) -> u64 { self.tree_count }
    pub fn tree_root(&self) -> [u8; 32] { self.tree_root }
    pub fn input_states(&self) -> &[InputState] { &self.input_states }
    pub fn output_states(&self) -> &[OutputState] { &self.output_states }
    pub fn creation(&self) -> Option<CreationState> { self.creation }
    pub fn response_digests(&self) -> &[[u8; 32]] { &self.response_digests }
    pub fn packet_digest(&self) -> Option<[u8; 32]> { self.packet_digest }
    pub fn appended_notes(&self) -> &[AppendedNote] { &self.appended_notes }
    pub fn consumed_nullifiers(&self) -> &[ConsumedNullifier] { &self.consumed_nullifiers }
    pub fn source_scope(&self) -> &'static str { "TRUSTED_NODE_AT_SELECTED_BLOCK" }

    // Sibling coherence consumer owns accepted payloads; no public acquired-state constructor.
    pub(super) fn into_history_parts(self) -> HistoryParts {
        HistoryParts {
            scope: self.scope, block_number: self.block_number, parent_hash: self.parent_hash,
            tree_id: self.tree_id, tree_count: self.tree_count, tree_root: self.tree_root,
            input_states: self.input_states, appended_notes: self.appended_notes,
            consumed_nullifiers: self.consumed_nullifiers,
        }
    }
}

pub(super) struct HistoryParts {
    pub scope: InspectionScope,
    pub block_number: U256,
    pub parent_hash: [u8; 32],
    pub tree_id: u32,
    pub tree_count: u64,
    pub tree_root: [u8; 32],
    pub input_states: Vec<InputState>,
    pub appended_notes: Vec<AppendedNote>,
    pub consumed_nullifiers: Vec<ConsumedNullifier>,
}

/// Node-reported void execution at one inspected block, NOT proof validity,
/// inclusion, finality, asset backing, signing permission or financial execution.
/// Only actual acquisition constructs it; no endpoint/provider bytes are retained.
#[derive(Debug)]
pub struct SimulationObservation {
    authority: AuthorityObservation,
    from: [u8; 20],
    to: [u8; 20],
    value: U256,
    gas_limit: u64,
    packet_digest: [u8; 32],
    calldata_sha256: [u8; 32],
    response_sha256: [u8; 32],
}

impl SimulationObservation {
    pub fn authority(&self) -> &AuthorityObservation { &self.authority }
    pub fn from(&self) -> [u8; 20] { self.from }
    pub fn to(&self) -> [u8; 20] { self.to }
    pub fn value(&self) -> U256 { self.value }
    pub fn gas_limit(&self) -> u64 { self.gas_limit }
    pub fn packet_digest(&self) -> [u8; 32] { self.packet_digest }
    pub fn calldata_sha256(&self) -> [u8; 32] { self.calldata_sha256 }
    pub fn response_sha256(&self) -> [u8; 32] { self.response_sha256 }
    pub fn source_scope(&self) -> &'static str { "TRUSTED_NODE_AT_SELECTED_BLOCK" }
    pub fn outcome(&self) -> &'static str { "NODE_REPORTED_VOID_EXECUTION" }
}

/// One concrete private endpoint; no defaults, proxy, redirect, retry or pool reuse.
pub struct SamechainInspectionClient {
    endpoint: Url,
    client: reqwest::Client,
}

impl fmt::Debug for SamechainInspectionClient {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SamechainInspectionClient").finish_non_exhaustive()
    }
}

impl SamechainInspectionClient {
    pub fn new(endpoint: &str, allow_loopback_http: bool) -> Result<Self, InspectionError> {
        let (endpoint, client) = crate::http::client(endpoint, allow_loopback_http, Duration::from_secs(30))
            .map_err(|error| match error {
                crate::http::HttpClientError::InvalidEndpoint => InspectionError::InvalidEndpoint,
                crate::http::HttpClientError::Transport => InspectionError::Transport,
            })?;
        Ok(Self { endpoint, client })
    }

    /// Inspect identity afresh, then execute the exact PUBLIC unsigned proposal
    /// through the same backend at the same canonical hash. Never signs or sends.
    pub async fn simulate(
        &self, scope: &InspectionScope, call: &UnsignedCall, gas_limit: u64,
    ) -> Result<SimulationObservation, SimulationError> {
        if gas_limit == 0 || gas_limit > MAX_SIMULATION_GAS {
            return Err(SimulationError::InvalidGas);
        }
        scope.validate().map_err(SimulationError::Inspection)?;
        if call.deployment() != &scope.expected || call.to() != scope.expected.authority
            || call.from() == [0; 20] || call.data().is_empty()
            || call.data().len() > super::MAX_CALLDATA_BYTES
        {
            return Err(SimulationError::InvalidCall);
        }
        let mut authority = self.inspect(scope, None).await.map_err(SimulationError::Inspection)?;
        // Move the acquired digest vector to continue this request sequence,
        // then separate the execution digest without copying identity receipts.
        let mut digests = std::mem::take(&mut authority.response_digests);
        let result: String = self.request("eth_call", json!([
            {"from":hex(&call.from()), "to":hex(&call.to()),
                "value":format!("0x{:x}", call.value()), "gas":format!("0x{gas_limit:x}"),
                "data":hex(call.data())},
            selected_block(scope),
        ]), &mut digests).await.map_err(|error| match error {
            InspectionError::RpcRejected(code) => SimulationError::RpcRejected(code),
            InspectionError::MalformedResponse => SimulationError::MalformedResponse,
            other => SimulationError::Inspection(other),
        })?;
        if result != "0x" { return Err(SimulationError::MalformedResponse); }
        let response_sha256 = digests.pop().ok_or(SimulationError::MalformedResponse)?;
        authority.response_digests = digests;
        Ok(SimulationObservation {
            authority, from: call.from(), to: call.to(), value: call.value(), gas_limit,
            packet_digest: call.packet_digest(), calldata_sha256: Sha256::digest(call.data()).into(),
            response_sha256,
        })
    }

    pub async fn inspect(
        &self,
        scope: &InspectionScope,
        packet: Option<InspectionPacket<'_>>,
    ) -> Result<AuthorityObservation, InspectionError> {
        scope.validate()?;
        let packet_digest = if let Some(packet) = packet {
            packet.validate()?;
            if packet.deployment() != &scope.expected
                || matches!(packet, InspectionPacket::Creation(packet) if packet.token != scope.token)
            {
                return Err(InspectionError::InvalidScope);
            }
            Some(packet.digest()?)
        } else { None };
        // Everything above is local and validated before ANY request or manifest iteration.
        let mut digests = Vec::with_capacity(24);
        let chain: String = self.request("eth_chainId", json!([]), &mut digests).await?;
        if quantity(&chain)? != U256::from(scope.expected.chain_id) {
            return Err(InspectionError::WrongChain);
        }
        // Deserialize the raw nested result directly: Value/from_value would erase
        // duplicate hash/number/parentHash keys before strict validation.
        let block: BlockResult = self.request(
            "eth_getBlockByHash", json!([hex(&scope.block_hash), false]), &mut digests,
        ).await?;
        if decode_fixed::<32>(&block.hash)? != scope.block_hash {
            return Err(InspectionError::WrongBlock);
        }
        let block_number = quantity(&block.number)?;
        let parent_hash = decode_fixed::<32>(&block.parent_hash)?;
        let deployment_words = self.call::<224>(scope, b"deployment()", &[], &mut digests).await?;
        let actual = decode_deployment(&deployment_words)?;
        if actual != scope.expected { return Err(InspectionError::WrongIdentity); }
        let deployment_digest = self.call::<32>(scope, b"deploymentDigest()", &[], &mut digests).await?;
        if deployment_digest != scope.expected.digest().map_err(|_| InspectionError::InvalidScope)? {
            return Err(InspectionError::WrongIdentity);
        }
        let token = self.call::<32>(scope, b"token()", &[], &mut digests).await?;
        if abi_address(&token)? != scope.token { return Err(InspectionError::WrongIdentity); }
        let token_code = self.call::<32>(scope, b"tokenCode()", &[], &mut digests).await?;
        if token_code != scope.token_code { return Err(InspectionError::WrongIdentity); }
        for (address, expected) in [
            (scope.expected.authority, scope.expected.authority_code),
            (scope.expected.verifier, scope.expected.verifier_code),
            (scope.token, scope.token_code),
        ] {
            let code: String = self.request("eth_getCode", json!([
                hex(&address), selected_block(scope),
            ]), &mut digests).await?;
            let code = decode_code(&code)?;
            let mut hash = [0; 32];
            let mut keccak = Keccak::v256();
            keccak.update(&code);
            keccak.finalize(&mut hash);
            if hash != expected { return Err(InspectionError::WrongIdentity); }
        }
        let tree = self.call::<96>(scope, b"treeState()", &[], &mut digests).await?;
        let tree_id = u32::try_from(abi_uint(&tree[..32], 4)?).map_err(|_| InspectionError::MalformedResponse)?;
        let tree_count = reported_count(&tree[32..64])?;
        let tree_root = tree[64..96].try_into().map_err(|_| InspectionError::MalformedResponse)?;
        if tree_root == [0; 32] { return Err(InspectionError::WrongState); }
        let mut input_states = Vec::with_capacity(match packet {
            Some(InspectionPacket::Fill(_)) => 2,
            Some(InspectionPacket::Single(_) | InspectionPacket::Withdrawal(_)) => 1,
            _ => 0,
        });
        match packet {
            Some(InspectionPacket::Fill(packet)) => {
                for input in &packet.inputs {
                    input_states.push(self.input(scope, (input.tree_id, input.index), input.root, input.nullifier, &mut digests).await?);
                }
            }
            Some(InspectionPacket::Single(packet)) => {
                let input = packet.input;
                input_states.push(self.input(scope, (input.tree_id, input.index), input.root, input.nullifier, &mut digests).await?);
            }
            Some(InspectionPacket::Withdrawal(packet)) => {
                let input = packet.input;
                input_states.push(self.input(scope, (input.tree_id, input.index), input.root, input.nullifier, &mut digests).await?);
            }
            _ => {}
        }
        let outputs = packet.as_ref().map_or(&[][..], InspectionPacket::outputs);
        let mut output_states = Vec::with_capacity(outputs.iter()
            .filter(|output| matches!(output, OutputDescriptor::Note { .. })).count());
        for (index, output) in outputs.iter().enumerate() {
            if let OutputDescriptor::Note { commitment, .. } = output {
                let word = self.call::<32>(scope, b"seenCommitments(bytes32)", &[*commitment], &mut digests).await?;
                output_states.push(OutputState {
                    manifest_index: index as u32, commitment: *commitment, reported_seen: abi_bool(&word)?,
                });
            }
        }
        let creation = if let Some(InspectionPacket::Creation(packet)) = packet {
            let mut payer = [0; 32];
            payer[12..].copy_from_slice(&packet.payer);
            let word = self.call::<32>(scope, b"usedCreationNonce(address,bytes32)", &[payer, packet.creation_nonce], &mut digests).await?;
            let nonce_used = abi_bool(&word)?;
            let initial_order_used = if let Some(order) = packet.order {
                let word = self.call::<32>(scope, b"usedInitialOrders(bytes32)", &[order.id], &mut digests).await?;
                Some(abi_bool(&word)?)
            } else { None };
            Some(CreationState { nonce_used, initial_order_used })
        } else { None };
        let appended_notes = self.appended_notes(scope, block_number, &mut digests).await?;
        let consumed_nullifiers = self.consumed_nullifiers(scope, block_number, &mut digests).await?;
        Ok(AuthorityObservation {
            scope: *scope, block_number, parent_hash, tree_id, tree_count, tree_root,
            input_states, output_states, creation, response_digests: digests, packet_digest,
            appended_notes, consumed_nullifiers,
        })
    }

    async fn input(
        &self, scope: &InspectionScope, position: (u32, u32),
        root: [u8; 32], nullifier: [u8; 32], digests: &mut Vec<[u8; 32]>,
    ) -> Result<InputState, InspectionError> {
        let (tree_id, index) = position;
        let mut tree = [0; 32];
        tree[28..].copy_from_slice(&tree_id.to_be_bytes());
        let count = self.call::<32>(scope, b"rootCounts(uint32,bytes32)", &[tree, root], digests).await?;
        let reported_root_count = reported_count(&count)?;
        let spent = self.call::<32>(scope, b"spent(bytes32)", &[nullifier], digests).await?;
        Ok(InputState { tree_id, index, root, nullifier, reported_root_count, reported_spent: abi_bool(&spent)? })
    }

    async fn appended_notes(
        &self, scope: &InspectionScope, block_number: U256,
        digests: &mut Vec<[u8; 32]>,
    ) -> Result<Vec<AppendedNote>, InspectionError> {
        let logs = self.event_logs(scope, block_number, note_appended_topic(), digests).await?;
        let mut notes = Vec::with_capacity(logs.len());
        let mut total_ciphertext = 0usize;
        for (occurrence, data) in logs {
            let note = decode_appended_note(&data, occurrence)?;
            total_ciphertext = total_ciphertext.checked_add(note.ciphertext.len())
                .ok_or(InspectionError::ResponseTooLarge)?;
            if total_ciphertext > MAX_APPENDED_CIPHERTEXT_BYTES {
                return Err(InspectionError::ResponseTooLarge);
            }
            if note.count > TREE_CAPACITY || note.index as u64 >= note.count {
                return Err(InspectionError::MalformedResponse);
            }
            notes.push(note);
        }
        Ok(notes)
    }

    async fn consumed_nullifiers(
        &self, scope: &InspectionScope, block_number: U256,
        digests: &mut Vec<[u8; 32]>,
    ) -> Result<Vec<ConsumedNullifier>, InspectionError> {
        self.event_logs(scope, block_number, nullifier_consumed_topic(), digests).await?
            .into_iter().map(|(occurrence, data)| decode_consumed_nullifier(&data, occurrence)).collect()
    }

    async fn event_logs(
        &self, scope: &InspectionScope, block_number: U256, topic: [u8; 32],
        digests: &mut Vec<[u8; 32]>,
    ) -> Result<Vec<(LogOccurrence, String)>, InspectionError> {
        let logs: Vec<LogResult> = self.request("eth_getLogs", json!([{
            "address": hex(&scope.expected.authority), "topics": [hex(&topic)],
            "blockHash": hex(&scope.block_hash),
        }]), digests).await?;
        if logs.len() > MAX_EVENTS_PER_KIND { return Err(InspectionError::ResponseTooLarge); }
        let mut order = OccurrenceOrder::default();
        let mut events = Vec::with_capacity(logs.len());
        for log in logs {
            let occurrence = validate_log(&log, scope, block_number, topic)?;
            order.observe(occurrence)?;
            events.push((occurrence, log.data));
        }
        Ok(events)
    }

    async fn call<const N: usize>(
        &self, scope: &InspectionScope, signature: &[u8], words: &[[u8; 32]],
        digests: &mut Vec<[u8; 32]>,
    ) -> Result<[u8; N], InspectionError> {
        let mut data = String::with_capacity(10 + words.len() * 64);
        append_hex(&mut data, &super::selector(signature), true);
        for word in words { append_hex(&mut data, word, false); }
        let result: String = self.request("eth_call", json!([
            {"to":hex(&scope.expected.authority), "data":data}, selected_block(scope),
        ]), digests).await?;
        decode_fixed(&result)
    }

    pub(crate) async fn request<T: for<'de> Deserialize<'de>>(
        &self, method: &str, params: serde_json::Value, digests: &mut Vec<[u8; 32]>,
    ) -> Result<T, InspectionError> {
        let id = digests.len() as u64 + 1;
        let mut response = self.client.post(self.endpoint.as_str())
            .json(&json!({"jsonrpc":"2.0", "id":id, "method":method, "params":params}))
            .send().await.map_err(|_| InspectionError::Transport)?;
        if !response.status().is_success() {
            return Err(InspectionError::HttpStatus(response.status().as_u16()));
        }
        if response.headers().contains_key(reqwest::header::CONTENT_ENCODING) {
            return Err(InspectionError::MalformedResponse);
        }
        let length = response.content_length();
        if length.is_some_and(|length| length > MAX_RESPONSE_BYTES as u64) {
            return Err(InspectionError::ResponseTooLarge);
        }
        let mut bytes = Vec::with_capacity(length.map_or(MAX_RESPONSE_BYTES, |length| length as usize));
        while let Some(chunk) = response.chunk().await.map_err(|_| InspectionError::Transport)? {
            if chunk.len() > MAX_RESPONSE_BYTES - bytes.len() {
                return Err(InspectionError::ResponseTooLarge);
            }
            bytes.extend_from_slice(&chunk);
        }
        let envelope: Envelope<T> = serde_json::from_slice(&bytes)
            .map_err(|_| InspectionError::MalformedResponse)?;
        if envelope.jsonrpc != "2.0" || envelope.id != id {
            return Err(InspectionError::MalformedResponse);
        }
        let result = match (envelope.result, envelope.error) {
            (Field::Present(result), Field::Missing) => result,
            (Field::Missing, Field::Present(error)) => return Err(InspectionError::RpcRejected(error.code)),
            _ => return Err(InspectionError::MalformedResponse),
        };
        digests.push(Sha256::digest(&bytes).into());
        Ok(result)
    }
}

struct LogResult {
    address: String,
    block_hash: String,
    block_number: String,
    transaction_hash: String,
    transaction_index: String,
    log_index: String,
    removed: bool,
    topics: Vec<String>,
    data: String,
}

fn validate_log(log: &LogResult, scope: &InspectionScope, block_number: U256,
    topic: [u8; 32]) -> Result<LogOccurrence, InspectionError>
{
    if decode_fixed::<20>(&log.address)? != scope.expected.authority
        || decode_fixed::<32>(&log.block_hash)? != scope.block_hash
        || quantity(&log.block_number)? != block_number || log.removed
        || log.topics.len() != 1 || decode_fixed::<32>(&log.topics[0])? != topic
    {
        return Err(InspectionError::MalformedResponse);
    }
    Ok(LogOccurrence {
        transaction_hash: decode_fixed(&log.transaction_hash)?,
        transaction_index: quantity_u64(&log.transaction_index)?,
        log_index: quantity_u64(&log.log_index)?,
    })
}

/// Same ordering/identity rule for each filtered RPC stream and their history merge.
#[derive(Default)]
pub(super) struct OccurrenceOrder {
    prior: Option<(u64, u64)>,
    indices: BTreeMap<u64, [u8; 32]>,
    transactions: BTreeMap<[u8; 32], u64>,
}

impl OccurrenceOrder {
    pub fn observe(&mut self, occurrence: LogOccurrence) -> Result<(), InspectionError> {
        let LogOccurrence { transaction_hash, transaction_index, log_index } = occurrence;
        if transaction_hash == [0; 32]
            || self.prior.is_some_and(|prior| prior >= (transaction_index, log_index) || prior.1 >= log_index)
            || self.indices.get(&transaction_index).is_some_and(|hash| *hash != transaction_hash)
            || self.transactions.get(&transaction_hash).is_some_and(|index| *index != transaction_index)
        {
            return Err(InspectionError::MalformedResponse);
        }
        self.prior = Some((transaction_index, log_index));
        self.indices.insert(transaction_index, transaction_hash);
        self.transactions.insert(transaction_hash, transaction_index);
        Ok(())
    }

    pub fn into_transactions(self) -> BTreeMap<[u8; 32], u64> { self.transactions }
}

impl<'de> Deserialize<'de> for LogResult {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        #[derive(Deserialize)]
        struct Fields {
            address: String,
            #[serde(rename = "blockHash")]
            block_hash: String,
            #[serde(rename = "blockNumber")]
            block_number: String,
            #[serde(rename = "transactionHash")]
            transaction_hash: String,
            #[serde(rename = "transactionIndex")]
            transaction_index: String,
            #[serde(rename = "logIndex")]
            log_index: String,
            removed: bool,
            topics: Vec<String>,
            data: String,
        }
        let fields: Fields = deserialize_object(deserializer)?;
        Ok(Self { address: fields.address, block_hash: fields.block_hash,
            block_number: fields.block_number, transaction_hash: fields.transaction_hash,
            transaction_index: fields.transaction_index, log_index: fields.log_index,
            removed: fields.removed, topics: fields.topics, data: fields.data })
    }
}

pub(crate) struct BlockResult {
    pub(crate) hash: String,
    pub(crate) number: String,
    pub(crate) parent_hash: String,
}

impl<'de> Deserialize<'de> for BlockResult {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        #[derive(Deserialize)]
        struct Fields { hash: String, number: String, #[serde(rename = "parentHash")] parent_hash: String }
        let fields: Fields = deserialize_object(deserializer)?;
        Ok(Self { hash: fields.hash, number: fields.number, parent_hash: fields.parent_hash })
    }
}

struct RpcError {
    code: i64,
    _message: String,
}

impl<'de> Deserialize<'de> for RpcError {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        #[derive(Deserialize)]
        struct Fields { code: i64, message: String }
        let fields: Fields = deserialize_object(deserializer)?;
        Ok(Self { code: fields.code, _message: fields.message })
    }
}

/// Distinguish absence from presence. T deserialization rejects null instead of
/// silently turning a null result/error into missing or a reported zero/false.
#[derive(Default)]
enum Field<T> {
    #[default]
    Missing,
    Present(T),
}
impl<'de, T: Deserialize<'de>> Deserialize<'de> for Field<T> {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        T::deserialize(deserializer).map(Self::Present)
    }
}

struct Envelope<T> {
    jsonrpc: String,
    id: u64,
    result: Field<T>,
    error: Field<RpcError>,
}

impl<'de, T: Deserialize<'de>> Deserialize<'de> for Envelope<T> {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        #[derive(Deserialize)]
        #[serde(bound(deserialize = "T: Deserialize<'de>"))]
        struct Fields<T> {
            jsonrpc: String,
            id: u64,
            #[serde(default)]
            result: Field<T>,
            #[serde(default)]
            error: Field<RpcError>,
        }
        let fields: Fields<T> = deserialize_object(deserializer)?;
        Ok(Self { jsonrpc: fields.jsonrpc, id: fields.id, result: fields.result, error: fields.error })
    }
}

// Serde's derived struct visitor also accepts positional sequences. Limit these
// three wire structs to raw JSON maps, then reuse derived duplicate/required-key
// handling through MapAccess WITHOUT collecting or collapsing fields in Value.
fn deserialize_object<'de, D: Deserializer<'de>, T: Deserialize<'de>>(
    deserializer: D,
) -> Result<T, D::Error> {
    struct ObjectVisitor<T>(std::marker::PhantomData<T>);
    impl<'de, T: Deserialize<'de>> Visitor<'de> for ObjectVisitor<T> {
        type Value = T;
        fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            f.write_str("a JSON object")
        }
        fn visit_map<A: MapAccess<'de>>(self, map: A) -> Result<T, A::Error> {
            T::deserialize(MapAccessDeserializer::new(map))
        }
    }
    deserializer.deserialize_map(ObjectVisitor(std::marker::PhantomData))
}

fn selected_block(scope: &InspectionScope) -> serde_json::Value {
    json!({"blockHash":hex(&scope.block_hash), "requireCanonical":true})
}

fn append_hex(text: &mut String, bytes: &[u8], prefix: bool) {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    if prefix { text.push_str("0x"); }
    for byte in bytes {
        text.push(DIGITS[(byte >> 4) as usize] as char);
        text.push(DIGITS[(byte & 15) as usize] as char);
    }
}

pub(crate) fn hex(bytes: &[u8]) -> String {
    let mut text = String::with_capacity(2 + bytes.len() * 2);
    append_hex(&mut text, bytes, true);
    text
}

fn nibble(byte: u8) -> Result<u8, InspectionError> {
    match byte {
        b'0'..=b'9' => Ok(byte - b'0'),
        b'a'..=b'f' => Ok(byte - b'a' + 10),
        b'A'..=b'F' => Ok(byte - b'A' + 10),
        _ => Err(InspectionError::MalformedResponse),
    }
}

fn decode_into(text: &str, output: &mut [u8]) -> Result<(), InspectionError> {
    let text = text.strip_prefix("0x").ok_or(InspectionError::MalformedResponse)?;
    if text.len() != output.len() * 2 { return Err(InspectionError::MalformedResponse); }
    for (byte, pair) in output.iter_mut().zip(text.as_bytes().as_chunks::<2>().0.iter()) {
        *byte = (nibble(pair[0])? << 4) | nibble(pair[1])?;
    }
    Ok(())
}

pub(crate) fn decode_fixed<const N: usize>(text: &str) -> Result<[u8; N], InspectionError> {
    let mut bytes = [0; N];
    decode_into(text, &mut bytes)?;
    Ok(bytes)
}

pub(crate) fn decode_code(text: &str) -> Result<Vec<u8>, InspectionError> {
    if text.len() > 2 + MAX_CODE_BYTES * 2 { return Err(InspectionError::ResponseTooLarge); }
    if text == "0x" { return Err(InspectionError::WrongIdentity); }
    if !text.starts_with("0x") || !(text.len() - 2).is_multiple_of(2) {
        return Err(InspectionError::MalformedResponse);
    }
    let mut bytes = vec![0; (text.len() - 2) / 2];
    decode_into(text, &mut bytes)?;
    Ok(bytes)
}

fn event_topic(signature: &[u8]) -> [u8; 32] {
    let mut topic = [0; 32];
    let mut keccak = Keccak::v256();
    keccak.update(signature);
    keccak.finalize(&mut topic);
    topic
}

fn note_appended_topic() -> [u8; 32] {
    event_topic(b"NoteAppended(bytes32,uint32,uint8,uint32,uint32,uint64,bytes32,bytes32,bytes32,uint16,bytes)")
}

fn nullifier_consumed_topic() -> [u8; 32] {
    event_topic(b"NullifierConsumed(bytes32,bytes32)")
}

fn decode_consumed_nullifier(text: &str, occurrence: LogOccurrence) -> Result<ConsumedNullifier, InspectionError> {
    let words = decode_fixed::<64>(text)?;
    let packet_digest = words[..32].try_into().map_err(|_| InspectionError::MalformedResponse)?;
    let nullifier = words[32..].try_into().map_err(|_| InspectionError::MalformedResponse)?;
    if packet_digest == [0; 32] || nullifier == [0; 32] {
        return Err(InspectionError::MalformedResponse);
    }
    Ok(ConsumedNullifier { occurrence, packet_digest, nullifier })
}

fn decode_appended_note(text: &str, occurrence: LogOccurrence) -> Result<AppendedNote, InspectionError> {
    let data = text.strip_prefix("0x").ok_or(InspectionError::MalformedResponse)?;
    if data.len() % 2 != 0 { return Err(InspectionError::MalformedResponse); }
    let byte_len = data.len() / 2;
    if byte_len > EVENT_HEAD_BYTES + 32 + MAX_CIPHERTEXT_BYTES.div_ceil(32) * 32 {
        return Err(InspectionError::ResponseTooLarge);
    }
    let mut bytes = vec![0; byte_len];
    decode_into(text, &mut bytes)?;
    if bytes.len() < EVENT_HEAD_BYTES + 32 { return Err(InspectionError::MalformedResponse); }
    let offset = abi_usize(&bytes[10 * 32..11 * 32])?;
    if offset != EVENT_HEAD_BYTES || offset % 32 != 0 || offset > bytes.len() - 32 {
        return Err(InspectionError::MalformedResponse);
    }
    let length = abi_usize(&bytes[offset..offset + 32])?;
    if length == 0 { return Err(InspectionError::MalformedResponse); }
    if length > MAX_CIPHERTEXT_BYTES { return Err(InspectionError::ResponseTooLarge); }
    let padded = length.checked_add(31).ok_or(InspectionError::ResponseTooLarge)? & !31;
    let end = offset.checked_add(32).and_then(|start| start.checked_add(padded))
        .ok_or(InspectionError::ResponseTooLarge)?;
    if end != bytes.len() { return Err(InspectionError::MalformedResponse); }
    if bytes[offset + 32 + length..end].iter().any(|byte| *byte != 0) {
        return Err(InspectionError::MalformedResponse);
    }
    let role = match abi_uint(&bytes[2 * 32..3 * 32], 1)? {
        0 => Role::A,
        1 => Role::B,
        _ => return Err(InspectionError::MalformedResponse),
    };
    let note = AppendedNote {
        occurrence,
        packet_digest: bytes[..32].try_into().map_err(|_| InspectionError::MalformedResponse)?,
        manifest_index: u32::try_from(abi_uint(&bytes[32..64], 4)?).map_err(|_| InspectionError::MalformedResponse)?,
        role,
        tree_id: u32::try_from(abi_uint(&bytes[3 * 32..4 * 32], 4)?).map_err(|_| InspectionError::MalformedResponse)?,
        index: u32::try_from(abi_uint(&bytes[4 * 32..5 * 32], 4)?).map_err(|_| InspectionError::MalformedResponse)?,
        count: abi_uint(&bytes[5 * 32..6 * 32], 8)?,
        root: bytes[6 * 32..7 * 32].try_into().map_err(|_| InspectionError::MalformedResponse)?,
        commitment: bytes[7 * 32..8 * 32].try_into().map_err(|_| InspectionError::MalformedResponse)?,
        recovery_key_commitment: bytes[8 * 32..9 * 32].try_into().map_err(|_| InspectionError::MalformedResponse)?,
        ciphertext_version: u16::try_from(abi_uint(&bytes[9 * 32..10 * 32], 2).map_err(|_| InspectionError::MalformedResponse)?).map_err(|_| InspectionError::MalformedResponse)?,
        ciphertext: bytes[offset + 32..offset + 32 + length].to_vec(),
    };
    if note.packet_digest == [0; 32] || note.root == [0; 32] || note.commitment == [0; 32]
        || note.recovery_key_commitment == [0; 32] || note.count == 0 || note.ciphertext_version == 0
    {
        return Err(InspectionError::MalformedResponse);
    }
    Ok(note)
}

fn abi_usize(word: &[u8]) -> Result<usize, InspectionError> {
    let value = abi_uint(word, 8)?;
    usize::try_from(value).map_err(|_| InspectionError::ResponseTooLarge)
}

pub(crate) fn quantity(text: &str) -> Result<U256, InspectionError> {
    let digits = text.strip_prefix("0x").ok_or(InspectionError::MalformedResponse)?;
    if digits.is_empty() || digits.len() > 64 || (digits.len() > 1 && digits.starts_with('0')) {
        return Err(InspectionError::MalformedResponse);
    }
    let mut number = U256::zero();
    for byte in digits.bytes() { number = (number << 4) | U256::from(nibble(byte)?); }
    Ok(number)
}
fn quantity_u64(text: &str) -> Result<u64, InspectionError> {
    let value = quantity(text)?;
    if value > U256::from(u64::MAX) { return Err(InspectionError::MalformedResponse); }
    Ok(value.low_u64())
}

pub(crate) fn abi_uint(word: &[u8], width: usize) -> Result<u64, InspectionError> {
    if word.len() != 32 || word[..32 - width].iter().any(|byte| *byte != 0) {
        return Err(InspectionError::MalformedResponse);
    }
    Ok(u64::from_be_bytes(word[24..].try_into().map_err(|_| InspectionError::MalformedResponse)?))
}

pub(crate) fn abi_address(word: &[u8]) -> Result<[u8; 20], InspectionError> {
    if word.len() != 32 || word[..12].iter().any(|byte| *byte != 0) {
        return Err(InspectionError::MalformedResponse);
    }
    word[12..].try_into().map_err(|_| InspectionError::MalformedResponse)
}

fn abi_bool(word: &[u8]) -> Result<bool, InspectionError> {
    match abi_uint(word, 1)? {
        0 => Ok(false),
        1 => Ok(true),
        _ => Err(InspectionError::MalformedResponse),
    }
}

fn reported_count(word: &[u8]) -> Result<u64, InspectionError> {
    let count = abi_uint(word, 8)?;
    if count > TREE_CAPACITY { return Err(InspectionError::WrongState); }
    Ok(count)
}

fn decode_deployment(bytes: &[u8; 224]) -> Result<Deployment, InspectionError> {
    Ok(Deployment {
        chain_id: abi_uint(&bytes[..32], 8)?,
        authority: abi_address(&bytes[32..64])?,
        authority_code: bytes[64..96].try_into().map_err(|_| InspectionError::MalformedResponse)?,
        verifier: abi_address(&bytes[96..128])?,
        verifier_code: bytes[128..160].try_into().map_err(|_| InspectionError::MalformedResponse)?,
        owner_program: bytes[160..192].try_into().map_err(|_| InspectionError::MalformedResponse)?,
        schema: u16::try_from(abi_uint(&bytes[192..224], 2)?).map_err(|_| InspectionError::MalformedResponse)?,
    })
}
