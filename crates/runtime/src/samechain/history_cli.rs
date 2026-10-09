//! Public pinned replay only: provider assumptions never become financial authority.
use std::{collections::BTreeSet, io::{self, Write}, path::{Path, PathBuf}};
use primitive_types::U256;
use serde::{Deserialize, Serialize, Serializer};
use ziquid_chains::samechain::history::{
    HistoryBlock, HistoryError, MAX_HISTORY_BLOCKS, PublicHistory,
};
use super::{
    InspectionDeployment, InspectionTree, SamechainInspectionClient, encode_appended_note,
    encode_consumed_nullifier, inspection_endpoint, inspection_error, inspection_scope,
    public_fixed_hex, public_hex,
};

const MAX_CONFIG_BYTES: usize = 1024 * 1024;
const MAX_EXPORT_BYTES: usize = 64 * 1024 * 1024;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Config {
    schema_version: u16,
    deployment: PathBuf,
    token: String,
    token_code: String,
    policy_id: String,
    endpoint_env: String,
    allow_loopback_http: bool,
    origin_number: String,
    block_hashes: Vec<String>,
}

pub(super) fn execute(path: &Path) -> Result<Vec<u8>, &'static str> {
    let bytes = crate::market::config::read_bytes(path, MAX_CONFIG_BYTES)
        .map_err(|_| "samechain history configuration unavailable or exceeds size limit")?;
    if bytes.iter().find(|byte| !byte.is_ascii_whitespace()) != Some(&b'{') {
        return Err("invalid samechain history configuration");
    }
    // Raw typed decode rejects duplicate keys, wrong types/nulls and trailing data.
    let config: Config = serde_json::from_slice(&bytes)
        .map_err(|_| "invalid samechain history configuration")?;
    if config.schema_version != 1 || config.block_hashes.is_empty()
        || config.block_hashes.len() > MAX_HISTORY_BLOCKS {
        return Err("invalid samechain history configuration");
    }
    let decimal = config.origin_number.as_bytes();
    if decimal.is_empty() || decimal.len() > 78 || !decimal.iter().all(u8::is_ascii_digit)
        || (decimal.len() > 1 && decimal[0] == b'0') {
        return Err("invalid samechain history origin number");
    }
    let origin_number = U256::from_dec_str(&config.origin_number)
        .map_err(|_| "invalid samechain history origin number")?;
    let (_, overflow) = origin_number.overflowing_add(U256::from(config.block_hashes.len() - 1));
    if overflow { return Err("samechain history block-number range overflow"); }
    // ALL independent pins are checked before deployment/endpoint acquisition or RPC.
    let mut pins = Vec::with_capacity(config.block_hashes.len());
    let mut unique = BTreeSet::new();
    for encoded in &config.block_hashes {
        let pin = public_fixed_hex::<32>(encoded)?;
        if !unique.insert(pin) { return Err("duplicate samechain history block pin"); }
        pins.push(pin);
    }
    let scope = inspection_scope(&config.deployment, &config.token, &config.token_code,
        &config.block_hashes[0], &config.policy_id)?;
    let mut history = PublicHistory::new(scope, origin_number).map_err(history_error)?;
    let endpoint = inspection_endpoint(&config.endpoint_env)?;
    let runtime = tokio::runtime::Builder::new_current_thread().enable_all().build()
        .map_err(|_| "samechain inspection runtime unavailable")?;
    runtime.block_on(async {
        // Client construction validates endpoint without sending an RPC. One client,
        // caller order, no retry/latest/range substitution or skipped empty blocks.
        let client = SamechainInspectionClient::new(&endpoint, config.allow_loopback_http)
            .map_err(inspection_error)?;
        for independent_pin in pins {
            let mut selected = scope;
            selected.block_hash = independent_pin;
            let observation = client.inspect(&selected, None).await.map_err(inspection_error)?;
            history.ingest(independent_pin, observation).map_err(history_error)?;
        }
        Ok::<(), &'static str>(())
    })?;
    let (tree_id, count, root) = history.tree_state();
    let deployment = &scope.expected;
    let export = Export {
        schema_version: 1, kind: "samechain_history_observation", status: "APPEND_STATE_COHERENT",
        source_scope: history.source_scope(), initial_boundary_trust: history.initial_boundary_trust(),
        log_completeness_trust: history.log_completeness_trust(),
        expected_deployment: InspectionDeployment {
            chain_id: deployment.chain_id.to_string(), authority: public_hex(&deployment.authority),
            authority_code: public_hex(&deployment.authority_code), verifier: public_hex(&deployment.verifier),
            verifier_code: public_hex(&deployment.verifier_code), owner_program: public_hex(&deployment.owner_program),
            schema: deployment.schema,
        },
        token: public_hex(&scope.token), token_code: public_hex(&scope.token_code),
        policy_id: public_hex(&scope.policy_id), origin_number: origin_number.to_string(),
        origin_hash: public_hex(&scope.block_hash), blocks: history.blocks(),
        tree: InspectionTree { tree_id, count, root: public_hex(&root) },
        block_count: history.block_count(), note_count: history.note_count(),
        nullifier_count: history.nullifier_count(), ciphertext_bytes: history.ciphertext_bytes(),
        note_order: "COMMITMENT_KEY", nullifier_order: "NULLIFIER_KEY",
        retained_notes: &history, observed_nullifiers: &history,
        finality: "UNVERIFIED", proof_validity: "UNVERIFIED", deployment_profile_qualification: "UNVERIFIED",
        root_eligibility: "UNVERIFIED", global_unspentness: "UNVERIFIED", asset_backing: "UNVERIFIED",
        signing: false, submission: false, financial_execution: false,
    };
    let mut writer = ExportWriter(Vec::new());
    serde_json::to_writer(&mut writer, &export).map_err(|_| "samechain history public export rejected")?;
    writer.write_all(b"\n").map_err(|_| "samechain history public export rejected")?;
    Ok(writer.0)
}

fn history_error(error: HistoryError) -> &'static str {
    match error {
        HistoryError::InvalidOrigin => "invalid samechain history origin",
        HistoryError::WrongScope => "samechain history scope mismatch",
        HistoryError::WrongBlock => "samechain history block discontinuity",
        HistoryError::InitialBoundary => "samechain history initial empty boundary rejected",
        HistoryError::TreeMismatch => "samechain history append/tree mismatch",
        HistoryError::DuplicateCommitment => "samechain history repeated commitment",
        HistoryError::DuplicateNullifier => "samechain history repeated observed nullifier",
        HistoryError::InvalidOccurrence => "samechain history occurrence rejected",
        HistoryError::InputMismatch => "samechain history queried input mismatch",
        HistoryError::LimitExceeded => "samechain history retention limit exceeded",
    }
}

#[derive(Serialize)]
struct Export<'a> {
    schema_version: u16,
    kind: &'static str,
    status: &'static str,
    source_scope: &'static str,
    initial_boundary_trust: &'static str,
    log_completeness_trust: &'static str,
    expected_deployment: InspectionDeployment,
    token: String,
    token_code: String,
    policy_id: String,
    origin_number: String,
    origin_hash: String,
    #[serde(serialize_with = "serialize_blocks")]
    blocks: &'a [HistoryBlock],
    tree: InspectionTree,
    block_count: usize,
    note_count: usize,
    nullifier_count: usize,
    ciphertext_bytes: usize,
    note_order: &'static str,
    nullifier_order: &'static str,
    #[serde(serialize_with = "serialize_notes")]
    retained_notes: &'a PublicHistory,
    #[serde(serialize_with = "serialize_nullifiers")]
    observed_nullifiers: &'a PublicHistory,
    finality: &'static str,
    proof_validity: &'static str,
    deployment_profile_qualification: &'static str,
    root_eligibility: &'static str,
    global_unspentness: &'static str,
    asset_backing: &'static str,
    signing: bool,
    submission: bool,
    financial_execution: bool,
}

#[derive(Serialize)]
struct BlockExport { number: String, hash: String, parent_hash: String }

fn encode_block(block: &HistoryBlock) -> BlockExport {
    BlockExport { number: block.number.to_string(), hash: public_hex(&block.hash),
        parent_hash: public_hex(&block.parent_hash) }
}

fn serialize_blocks<S: Serializer>(blocks: &[HistoryBlock], serializer: S) -> Result<S::Ok, S::Error> {
    serializer.collect_seq(blocks.iter().map(encode_block))
}

fn serialize_notes<S: Serializer>(history: &PublicHistory, serializer: S) -> Result<S::Ok, S::Error> {
    #[derive(Serialize)]
    struct NoteExport<'a> {
        block: BlockExport,
        #[serde(flatten)]
        note: super::InspectionAppendedNote,
        #[serde(serialize_with = "serialize_siblings")]
        insertion_siblings: &'a [[u8; 32]; 32],
    }
    // Borrow the retained history and hex-encode just one bounded note at a time;
    // neither acquired ciphertext Vecs nor a second growing export vector is cloned.
    serializer.collect_seq(history.notes().map(|retained| NoteExport {
        block: encode_block(&retained.block), note: encode_appended_note(&retained.note),
        insertion_siblings: &retained.insertion.siblings,
    }))
}

fn serialize_siblings<S: Serializer>(siblings: &[[u8; 32]; 32], serializer: S) -> Result<S::Ok, S::Error> {
    serializer.collect_seq(siblings.iter().map(|hash| public_hex(hash)))
}

fn serialize_nullifiers<S: Serializer>(history: &PublicHistory, serializer: S) -> Result<S::Ok, S::Error> {
    #[derive(Serialize)]
    struct NullifierExport {
        block: BlockExport,
        #[serde(flatten)]
        event: super::InspectionConsumedNullifier,
    }
    serializer.collect_seq(history.nullifiers().map(|observed| NullifierExport {
        block: encode_block(&observed.block), event: encode_consumed_nullifier(&observed.event),
    }))
}

/// Buffer before stdout so acquisition/serialization/size errors export no partial result.
struct ExportWriter(Vec<u8>);

impl Write for ExportWriter {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        let length = self.0.len().checked_add(bytes.len()).filter(|length| *length <= MAX_EXPORT_BYTES)
            .ok_or_else(|| io::Error::other("history export exceeds size limit"))?;
        if length > self.0.capacity() {
            // Geometric growth for normal serialization, clamped BEFORE allocation.
            let capacity = self.0.capacity().saturating_mul(2).max(length).clamp(4096, MAX_EXPORT_BYTES);
            self.0.try_reserve_exact(capacity - self.0.len())
                .map_err(|_| io::Error::other("history export buffer unavailable"))?;
        }
        self.0.extend_from_slice(bytes);
        Ok(bytes.len())
    }
    fn flush(&mut self) -> io::Result<()> { Ok(()) }
}
