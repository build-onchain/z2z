//! Exact public state acquired from one independently pinned native deployment.
//!
//! TRUSTED node coherence is not consensus, source acceptance/finality, program
//! qualification, proof validity, ETH backing or evidence of an actual transfer.
//! No observation authorizes source release, refund, signing or Completed state.

use std::{error::Error, fmt, time::Duration};
use primitive_types::U256;
use serde::Deserialize;
use serde_json::json;
use tiny_keccak::{Hasher, Keccak};
use url::Url;
use ziquid_protocol::native::{DeploymentDescriptor, Statement};
use crate::samechain::inspection::{
    BlockResult, InspectionError, abi_address, abi_bool, abi_uint, decode_code,
    decode_fixed, hex, quantity, rpc_request,
};

/// Categorical only: no URL, provider message, raw response or revert bytes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum NativeInspectionError {
    InvalidEndpoint,
    InvalidScope,
    InvalidStatement,
    Transport,
    HttpRejected,
    ResponseTooLarge,
    RpcRejected,
    MalformedResponse,
    WrongChain,
    WrongBlock,
    WrongIdentity,
    WrongState,
}

impl NativeInspectionError {
    pub const fn message(self) -> &'static str {
        match self {
            Self::InvalidEndpoint => "invalid native inspection endpoint",
            Self::InvalidScope => "invalid native inspection scope",
            Self::InvalidStatement => "invalid native inspection statement",
            Self::Transport => "native inspection transport unavailable",
            Self::HttpRejected => "native inspection HTTP rejected",
            Self::ResponseTooLarge => "native inspection response exceeds size limit",
            Self::RpcRejected => "native inspection RPC rejected",
            Self::MalformedResponse => "invalid native inspection response",
            Self::WrongChain => "native inspection chain mismatch",
            Self::WrongBlock => "native inspection block mismatch",
            Self::WrongIdentity => "native inspection identity mismatch",
            Self::WrongState => "native inspection state rejected",
        }
    }
}
impl fmt::Display for NativeInspectionError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result { f.write_str(self.message()) }
}
impl Error for NativeInspectionError {}
impl From<InspectionError> for NativeInspectionError {
    fn from(error: InspectionError) -> Self {
        match error {
            InspectionError::InvalidEndpoint => Self::InvalidEndpoint,
            InspectionError::InvalidScope => Self::InvalidScope,
            InspectionError::InvalidPacket => Self::InvalidStatement,
            InspectionError::Transport => Self::Transport,
            InspectionError::HttpStatus(_) => Self::HttpRejected,
            InspectionError::ResponseTooLarge => Self::ResponseTooLarge,
            InspectionError::RpcRejected(_) => Self::RpcRejected,
            InspectionError::MalformedResponse => Self::MalformedResponse,
            InspectionError::WrongChain => Self::WrongChain,
            InspectionError::WrongBlock => Self::WrongBlock,
            InspectionError::WrongIdentity => Self::WrongIdentity,
            InspectionError::WrongState => Self::WrongState,
        }
    }
}

/// Full independently retained pins and an explicit nonzero target block hash.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct NativeInspectionScope {
    pub expected: DeploymentDescriptor,
    pub block_hash: [u8; 32],
}
impl NativeInspectionScope {
    pub fn validate(&self) -> Result<(), NativeInspectionError> {
        if self.block_hash == [0; 32] || self.expected.validate().is_err()
            || [self.expected.financial_program, self.expected.origin_program,
                self.expected.source_acceptance_program].iter().any(|program| *program >= super::SCALAR_MODULUS)
        {
            return Err(NativeInspectionError::InvalidScope);
        }
        Ok(())
    }
}

/// Private immutable row fields, exposed only after all selected-block reads
/// match. An all-zero absent row is not refund eligibility; consumed is only
/// the node's reported bit, not an authenticated beneficiary transfer.
#[derive(Debug)]
pub struct NativeObligationObservation {
    context_digest: [u8; 32],
    queried_stable_jtag: [u8; 32],
    d: U256,
    a: u64,
    payer: [u8; 20],
    u_payee: [u8; 20],
    s_refund: [u8; 20],
    stable_jtag: [u8; 32],
    reported_armed: bool,
    reported_consumed: bool,
    reported_tag_context: [u8; 32],
}
impl NativeObligationObservation {
    pub fn context_digest(&self) -> [u8; 32] { self.context_digest }
    pub fn queried_stable_jtag(&self) -> [u8; 32] { self.queried_stable_jtag }
    pub fn d(&self) -> U256 { self.d }
    pub fn a(&self) -> u64 { self.a }
    pub fn payer(&self) -> [u8; 20] { self.payer }
    pub fn u_payee(&self) -> [u8; 20] { self.u_payee }
    pub fn s_refund(&self) -> [u8; 20] { self.s_refund }
    pub fn stable_jtag(&self) -> [u8; 32] { self.stable_jtag }
    pub fn reported_armed(&self) -> bool { self.reported_armed }
    pub fn reported_consumed(&self) -> bool { self.reported_consumed }
    pub fn reported_tag_context(&self) -> [u8; 32] { self.reported_tag_context }
}

/// Constructed only by actual bounded acquisition, never deserialized or
/// caller-forged. No endpoint, certificate or financial-completion flag.
#[derive(Debug)]
pub struct NativeInspectionObservation {
    scope: NativeInspectionScope,
    block_number: U256,
    parent_hash: [u8; 32],
    total_liability: U256,
    obligation: Option<NativeObligationObservation>,
    response_digests: Vec<[u8; 32]>,
}
impl NativeInspectionObservation {
    pub fn deployment(&self) -> &DeploymentDescriptor { &self.scope.expected }
    pub fn block_hash(&self) -> [u8; 32] { self.scope.block_hash }
    pub fn block_number(&self) -> U256 { self.block_number }
    pub fn parent_hash(&self) -> [u8; 32] { self.parent_hash }
    pub fn total_liability(&self) -> U256 { self.total_liability }
    pub fn obligation(&self) -> Option<&NativeObligationObservation> { self.obligation.as_ref() }
    pub fn response_digests(&self) -> &[[u8; 32]] { &self.response_digests }
    pub fn source_scope(&self) -> &'static str { "TRUSTED_NODE_AT_SELECTED_BLOCK" }
    pub fn finality(&self) -> &'static str { "UNVERIFIED" }
    pub fn program_qualification(&self) -> &'static str { "UNVERIFIED" }
    pub fn proof_validity(&self) -> &'static str { "UNVERIFIED" }
    pub fn asset_backing(&self) -> &'static str { "UNVERIFIED" }
    pub fn actual_transfer(&self) -> &'static str { "UNVERIFIED" }
}

/// One private endpoint under the existing TLS/literal-loopback HTTP policy.
/// No default endpoint, redirect, proxy, retry, latest-block fallback or send.
pub struct NativeInspectionClient {
    endpoint: Url,
    client: reqwest::Client,
}
impl fmt::Debug for NativeInspectionClient {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("NativeInspectionClient").finish_non_exhaustive()
    }
}
impl NativeInspectionClient {
    pub fn new(endpoint: &str, allow_loopback_http: bool) -> Result<Self, NativeInspectionError> {
        let (endpoint, client) = crate::http::client(endpoint, allow_loopback_http, Duration::from_secs(30))
            .map_err(|error| match error {
                crate::http::HttpClientError::InvalidEndpoint => NativeInspectionError::InvalidEndpoint,
                crate::http::HttpClientError::Transport => NativeInspectionError::Transport,
            })?;
        Ok(Self { endpoint, client })
    }

    /// All scope and optional canonical statement bindings are checked locally
    /// before any RPC. Calls and runtime code are EIP-1898 hash/canonical pinned.
    pub async fn inspect(
        &self, scope: &NativeInspectionScope, statement: Option<&Statement>,
    ) -> Result<NativeInspectionObservation, NativeInspectionError> {
        scope.validate()?;
        if let Some(statement) = statement {
            super::check_statement(&scope.expected, statement)
                .map_err(|_| NativeInspectionError::InvalidStatement)?;
        }
        let mut digests = Vec::with_capacity(if statement.is_some() { 9 } else { 7 });
        let chain: String = self.request("eth_chainId", json!([]), &mut digests).await?;
        if quantity(&chain)? != U256::from(scope.expected.target_chain_id) {
            return Err(NativeInspectionError::WrongChain);
        }
        let block: BlockResult = self.request("eth_getBlockByHash",
            json!([hex(&scope.block_hash), false]), &mut digests).await?;
        if decode_fixed::<32>(&block.hash)? != scope.block_hash {
            return Err(NativeInspectionError::WrongBlock);
        }
        let block_number = quantity(&block.number)?;
        let parent_hash = decode_fixed(&block.parent_hash)?;
        // Actual NativeFinancialCodec.DeploymentDescriptor is 14 static ABI
        // words (448 bytes), not the 279-byte packed canonical descriptor.
        let bytes = self.call::<448>(scope, b"deployment()", &[], &mut digests).await?;
        if decode_deployment(&bytes)? != scope.expected { return Err(NativeInspectionError::WrongIdentity); }
        let digest = self.call::<32>(scope, b"deploymentDigest()", &[], &mut digests).await?;
        if digest != scope.expected.digest() { return Err(NativeInspectionError::WrongIdentity); }
        for (address, expected) in [
            (scope.expected.obligation, scope.expected.obligation_runtime_code),
            (scope.expected.verifier, scope.expected.verifier_runtime_code),
        ] {
            let code: String = self.request("eth_getCode", json!([
                hex(&address), selected_block(scope),
            ]), &mut digests).await?;
            let code = decode_code(&code)?;
            let mut actual = [0; 32];
            let mut keccak = Keccak::v256(); keccak.update(&code); keccak.finalize(&mut actual);
            if actual != expected { return Err(NativeInspectionError::WrongIdentity); }
        }
        let liability = self.call::<32>(scope, b"totalLiability()", &[], &mut digests).await?;
        let total_liability = U256::from_big_endian(&liability);
        let obligation = if let Some(statement) = statement {
            let context = statement.digest();
            let bytes = self.call::<256>(scope, b"obligations(bytes32)", &[context], &mut digests).await?;
            let tag_context = self.call::<32>(scope, b"contextForTag(bytes32)", &[statement.stable_jtag], &mut digests).await?;
            Some(decode_obligation(&bytes, statement, context, tag_context, total_liability)?)
        } else { None };
        Ok(NativeInspectionObservation {
            scope: *scope, block_number, parent_hash, total_liability, obligation, response_digests: digests,
        })
    }

    async fn request<T: for<'de> Deserialize<'de>>(
        &self, method: &str, params: serde_json::Value, digests: &mut Vec<[u8; 32]>,
    ) -> Result<T, NativeInspectionError> {
        rpc_request(&self.client, &self.endpoint, method, params, digests).await.map_err(Into::into)
    }

    async fn call<const N: usize>(
        &self, scope: &NativeInspectionScope, signature: &[u8], words: &[[u8; 32]],
        digests: &mut Vec<[u8; 32]>,
    ) -> Result<[u8; N], NativeInspectionError> {
        let mut data = super::calldata(signature, 4 + words.len() * 32);
        for word in words { data.extend_from_slice(word); }
        let result: String = self.request("eth_call", json!([
            {"to":hex(&scope.expected.obligation), "data":hex(&data)}, selected_block(scope),
        ]), digests).await?;
        decode_fixed(&result).map_err(Into::into)
    }
}

fn selected_block(scope: &NativeInspectionScope) -> serde_json::Value {
    json!({"blockHash":hex(&scope.block_hash), "requireCanonical":true})
}
fn decode_deployment(bytes: &[u8; 448]) -> Result<DeploymentDescriptor, NativeInspectionError> {
    let words = bytes.as_chunks::<32>().0;
    Ok(DeploymentDescriptor {
        schema_version: abi_uint(&words[0], 2)? as u16,
        source_network: abi_uint(&words[1], 1)? as u8,
        source_pool: abi_uint(&words[2], 1)? as u8,
        transaction_version: abi_uint(&words[3], 4)? as u32,
        consensus_branch: abi_uint(&words[4], 4)? as u32,
        financial_program: words[5], origin_program: words[6],
        source_acceptance_program: words[7], source_policy_id: words[8],
        target_chain_id: abi_uint(&words[9], 8)?, obligation: abi_address(&words[10])?,
        obligation_runtime_code: words[11], verifier: abi_address(&words[12])?,
        verifier_runtime_code: words[13],
    })
}
fn decode_obligation(
    bytes: &[u8; 256], statement: &Statement, context: [u8; 32], tag_context: [u8; 32], total_liability: U256,
) -> Result<NativeObligationObservation, NativeInspectionError> {
    let words = bytes.as_chunks::<32>().0;
    let row = NativeObligationObservation {
        context_digest: context, queried_stable_jtag: statement.stable_jtag,
        d: U256::from_big_endian(&words[0]), a: abi_uint(&words[1], 8)?,
        payer: abi_address(&words[2])?, u_payee: abi_address(&words[3])?, s_refund: abi_address(&words[4])?,
        stable_jtag: words[5], reported_armed: abi_bool(&words[6])?, reported_consumed: abi_bool(&words[7])?,
        reported_tag_context: tag_context,
    };
    if !row.reported_armed {
        // A different reserved context is a reachable conflict, not a free tag.
        if bytes.iter().any(|byte| *byte != 0) || tag_context == context {
            return Err(NativeInspectionError::WrongState);
        }
    } else if row.d != U256::from_big_endian(&statement.d) || row.a != statement.a
        || row.payer != statement.payer || row.u_payee != statement.u_payee
        || row.s_refund != statement.s_refund || row.stable_jtag != statement.stable_jtag
        || tag_context != context || (!row.reported_consumed && total_liability < row.d)
    {
        return Err(NativeInspectionError::WrongState);
    }
    Ok(row)
}
