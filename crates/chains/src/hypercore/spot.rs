//! Exact offline spot proposals, not signing material or venue execution.
//!
//! The local SHA256 digest binds review choices only. Requested fee caps are
//! not present in the venue action and cannot be enforced by these constructors.

use super::{Account, Cloid, ExactDecimal, Network, OrderId, Side, SpotMarket};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{fmt, io};

const SCHEMA_VERSION: u16 = 1;
const DIGEST_DOMAIN: &[u8] = b"Z2Z_HYPERCORE_SPOT_PROPOSAL\0";
const MAX_TERM_BYTES: usize = 512;

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub enum SpotTif {
    Gtc,
    Alo,
    Ioc,
}

/// One exact token's requested atom cap, not a complete execution fee policy.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FeeCap {
    pub token_id: String,
    pub max_atoms: String,
}

#[derive(Clone, Debug)]
pub struct SpotOrderIntent {
    pub network: Network,
    pub account: Account,
    pub nonce: u64,
    pub expires_after_ms: u64,
    pub cloid: Cloid,
    pub side: Side,
    pub size: String,
    pub limit_price: String,
    pub tif: SpotTif,
    pub fee_cap: FeeCap,
}

#[derive(Clone, Debug)]
pub struct SpotCancelIntent {
    pub network: Network,
    pub account: Account,
    pub nonce: u64,
    pub expires_after_ms: u64,
    pub order: OrderId,
}

/// Fixed diagnostics never contain caller terms, paths, or transport details.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SpotPreparationError {
    InvalidNumber,
    InvalidPrecision,
    InvalidFeeCap,
    InvalidNonce,
    InvalidOrder,
    Encoding,
    InputBounds,
}

impl fmt::Display for SpotPreparationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::InvalidNumber => "invalid spot number",
            Self::InvalidPrecision => "invalid spot precision",
            Self::InvalidFeeCap => "invalid spot fee cap",
            Self::InvalidNonce => "invalid spot nonce",
            Self::InvalidOrder => "invalid spot order",
            Self::Encoding => "invalid spot encoding",
            Self::InputBounds => "spot input bounds exceeded",
        })
    }
}

impl std::error::Error for SpotPreparationError {}

// This single substantive record is serialized in the output and hashed in
// exactly this field order. Its action_json is the retained typed wire string.
#[derive(Clone, Debug, Serialize)]
struct ProposalRecord {
    kind: &'static str,
    network: Network,
    account: Account,
    signer: Account,
    nonce: u64,
    expires_after_ms: u64,
    market: SpotMarket,
    #[serde(skip_serializing_if = "Option::is_none")]
    fee_cap: Option<FeeCap>,
    action_json: String,
}

/// Immutable validated proposal. Deserialization cannot fabricate readiness.
#[derive(Clone, Debug, Serialize)]
pub struct PreparedSpotIntent {
    schema_version: u16,
    #[serde(flatten)]
    record: ProposalRecord,
    intent_digest: [u8; 32],
    source_validity: &'static str,
    fee_cap_enforcement: &'static str,
    signing_material_generated: bool,
    signing_ready: bool,
    submission_ready: bool,
    durable_reservation: bool,
    account_mode: &'static str,
    nonce_validity: &'static str,
    outcome: &'static str,
}

impl PreparedSpotIntent {
    pub fn action_json(&self) -> &str {
        &self.record.action_json
    }

    pub fn intent_digest(&self) -> [u8; 32] {
        self.intent_digest
    }
}

// Field order is deliberate. Do not round-trip these actions through Value.
#[derive(Serialize)]
struct OrderAction<'a> {
    #[serde(rename = "type")]
    action_type: &'static str,
    orders: [WireOrder<'a>; 1],
    grouping: &'static str,
}

#[derive(Serialize)]
struct WireOrder<'a> {
    a: u32,
    b: bool,
    p: &'a str,
    s: &'a str,
    r: bool,
    t: OrderType,
    c: Cloid,
}

#[derive(Serialize)]
struct OrderType {
    limit: LimitOrder,
}

#[derive(Serialize)]
struct LimitOrder {
    tif: SpotTif,
}

#[derive(Serialize)]
struct CancelAction<T> {
    #[serde(rename = "type")]
    action_type: &'static str,
    cancels: [T; 1],
}

#[derive(Serialize)]
struct OidCancel {
    a: u32,
    o: u64,
}

#[derive(Serialize)]
struct CloidCancel {
    asset: u32,
    cloid: Cloid,
}

pub fn prepare_spot_order(
    market: &SpotMarket,
    intent: &SpotOrderIntent,
) -> Result<PreparedSpotIntent, SpotPreparationError> {
    if [&intent.size, &intent.limit_price, &intent.fee_cap.token_id, &intent.fee_cap.max_atoms]
        .into_iter().any(|text| text.len() > MAX_TERM_BYTES)
    {
        return Err(SpotPreparationError::InputBounds);
    }
    validate_nonce(intent.nonce, intent.expires_after_ms)?;
    validate_cloid(intent.cloid)?;
    let size = positive_decimal(&intent.size)?;
    let price = positive_decimal(&intent.limit_price)?;
    if fractional_digits(size.as_str()) > usize::from(market.size_decimals()) {
        return Err(SpotPreparationError::InvalidPrecision);
    }
    let price_fraction = fractional_digits(price.as_str());
    if price_fraction > usize::from(8 - market.size_decimals())
        || (price_fraction != 0 && significant_digits(price.as_str()) > 5)
    {
        return Err(SpotPreparationError::InvalidPrecision);
    }
    let fee_cap = validated_cap(market, &intent.fee_cap)?;
    let action_json = serde_json::to_string(&OrderAction {
        action_type: "order",
        orders: [WireOrder {
            a: market.action_asset(),
            b: intent.side == Side::Buy,
            p: price.as_str(),
            s: size.as_str(),
            r: false,
            t: OrderType { limit: LimitOrder { tif: intent.tif } },
            c: intent.cloid,
        }],
        grouping: "na",
    }).map_err(|_| SpotPreparationError::Encoding)?;
    prepare(ProposalRecord {
        kind: "order",
        network: intent.network,
        account: intent.account,
        signer: intent.account,
        nonce: intent.nonce,
        expires_after_ms: intent.expires_after_ms,
        market: market.clone(),
        fee_cap: Some(fee_cap),
        action_json,
    })
}

pub fn prepare_spot_cancel(
    market: &SpotMarket,
    intent: &SpotCancelIntent,
) -> Result<PreparedSpotIntent, SpotPreparationError> {
    validate_nonce(intent.nonce, intent.expires_after_ms)?;
    let action_json = match intent.order {
        OrderId::Oid(0) => return Err(SpotPreparationError::InvalidOrder),
        OrderId::Oid(oid) => serde_json::to_string(&CancelAction {
            action_type: "cancel",
            cancels: [OidCancel { a: market.action_asset(), o: oid }],
        }),
        OrderId::Cloid(cloid) => {
            validate_cloid(cloid)?;
            serde_json::to_string(&CancelAction {
                action_type: "cancelByCloid",
                cancels: [CloidCancel { asset: market.action_asset(), cloid }],
            })
        }
    }.map_err(|_| SpotPreparationError::Encoding)?;
    prepare(ProposalRecord {
        kind: "cancel",
        network: intent.network,
        account: intent.account,
        signer: intent.account,
        nonce: intent.nonce,
        expires_after_ms: intent.expires_after_ms,
        market: market.clone(),
        fee_cap: None,
        action_json,
    })
}

fn validate_nonce(nonce: u64, expiry: u64) -> Result<(), SpotPreparationError> {
    if nonce == 0 || expiry <= nonce {
        return Err(SpotPreparationError::InvalidNonce);
    }
    Ok(())
}

fn validate_cloid(cloid: Cloid) -> Result<(), SpotPreparationError> {
    if cloid.0 == [0; 16] {
        return Err(SpotPreparationError::InvalidOrder);
    }
    Ok(())
}

fn positive_decimal(text: &str) -> Result<ExactDecimal, SpotPreparationError> {
    let normalized = match text.split_once('.') {
        Some((integer, fraction)) => {
            if integer.is_empty() || fraction.is_empty()
                || !fraction.bytes().all(|byte| byte.is_ascii_digit())
            {
                return Err(SpotPreparationError::InvalidNumber);
            }
            let trimmed = text.trim_end_matches('0');
            trimmed.strip_suffix('.').unwrap_or(trimmed)
        }
        None => text,
    };
    if !normalized.bytes().any(|byte| matches!(byte, b'1'..=b'9'))
        || normalized.starts_with('-')
    {
        return Err(SpotPreparationError::InvalidNumber);
    }
    ExactDecimal::parse(normalized).map_err(|_| SpotPreparationError::InvalidNumber)
}

fn fractional_digits(text: &str) -> usize {
    text.split_once('.').map_or(0, |(_, fraction)| fraction.len())
}

fn significant_digits(text: &str) -> usize {
    text.bytes().filter(|byte| *byte != b'.')
        .skip_while(|byte| *byte == b'0').count()
}

fn validated_cap(market: &SpotMarket, cap: &FeeCap) -> Result<FeeCap, SpotPreparationError> {
    if !(cap.token_id.eq_ignore_ascii_case(market.base_token_id())
        || cap.token_id.eq_ignore_ascii_case(market.quote_token_id()))
        || cap.max_atoms.is_empty()
        || (cap.max_atoms.len() > 1 && cap.max_atoms.starts_with('0'))
        || !cap.max_atoms.bytes().all(|byte| byte.is_ascii_digit())
    {
        return Err(SpotPreparationError::InvalidFeeCap);
    }
    // Reuse the checked U256 response validator without copying atom digits.
    ExactDecimal::validate(&cap.max_atoms).map_err(|_| SpotPreparationError::InvalidFeeCap)?;
    Ok(FeeCap {
        token_id: cap.token_id.to_ascii_lowercase(),
        max_atoms: cap.max_atoms.clone(),
    })
}

struct DigestWriter(Sha256);

impl io::Write for DigestWriter {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        self.0.update(bytes);
        Ok(bytes.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

fn prepare(record: ProposalRecord) -> Result<PreparedSpotIntent, SpotPreparationError> {
    let mut writer = DigestWriter(Sha256::new());
    writer.0.update(DIGEST_DOMAIN);
    writer.0.update(SCHEMA_VERSION.to_be_bytes());
    serde_json::to_writer(&mut writer, &record).map_err(|_| SpotPreparationError::Encoding)?;
    let intent_digest = writer.0.finalize().into();
    Ok(PreparedSpotIntent {
        schema_version: SCHEMA_VERSION,
        record,
        intent_digest,
        source_validity: "UNVERIFIED",
        fee_cap_enforcement: "NotVenueEnforced",
        signing_material_generated: false,
        signing_ready: false,
        submission_ready: false,
        durable_reservation: false,
        account_mode: "UNVERIFIED",
        nonce_validity: "UNVERIFIED",
        outcome: "PreparedProposal",
    })
}
