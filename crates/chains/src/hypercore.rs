//! Explicit HyperCore testnet information, never settlement evidence.
//!
//! HTTPS and decoding do not establish funds, complete history, finality, or
//! permission to release money. This surface contains no exchange/action API.

pub mod spot;

use primitive_types::U256;
use serde::{Deserialize, Deserializer, Serialize, Serializer, de, ser::SerializeMap};
use sha2::{Digest, Sha256};
use std::{
    collections::{BTreeMap, BTreeSet},
    fmt,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

pub const MAX_INFO_RESPONSE_BYTES: usize = 2 * 1024 * 1024;
pub const TESTNET_INFO_ENDPOINT: &str = "https://api.hyperliquid-testnet.xyz/info";
const MAX_FILLS: usize = 2_000;
const RETAINED_FILLS: usize = 10_000;
const MAX_DECIMAL_SCALE: u32 = 77;

/// Errors intentionally contain neither account/URL nor response/transport text.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum HyperCoreError {
    AssetMismatch,
    InvalidMetadata,
    InvalidDecimal,
    InvalidAccount,
    InvalidCloid,
    InvalidTimeRange,
    RequestMismatch,
    MalformedResponse,
    ResponseTooLarge,
    HttpStatus(u16),
    Timeout,
    Transport,
    ClientConfiguration,
    Clock,
}

impl fmt::Display for HyperCoreError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::HttpStatus(status) => write!(f, "HyperCore info HTTP status {status}"),
            Self::AssetMismatch => f.write_str("HyperCore spot asset identity mismatch"),
            Self::InvalidMetadata => f.write_str("invalid HyperCore spot metadata"),
            Self::InvalidDecimal => f.write_str("invalid exact HyperCore decimal"),
            Self::InvalidAccount => f.write_str("invalid HyperCore account identity"),
            Self::InvalidCloid => f.write_str("invalid HyperCore client order identity"),
            Self::InvalidTimeRange => f.write_str("invalid HyperCore time range"),
            Self::RequestMismatch => f.write_str("HyperCore response does not match request scope"),
            Self::MalformedResponse => f.write_str("malformed HyperCore info response"),
            Self::ResponseTooLarge => f.write_str("HyperCore info response exceeds byte limit"),
            Self::Timeout => f.write_str("HyperCore info request timed out"),
            Self::Transport => f.write_str("HyperCore info transport failed"),
            Self::ClientConfiguration => f.write_str("HyperCore info client configuration failed"),
            Self::Clock => f.write_str("HyperCore observation clock is out of range"),
        }
    }
}

impl std::error::Error for HyperCoreError {}

/// There is deliberately no default, mainnet variant, or caller-supplied URL.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Network {
    Testnet,
}

fn hex_bytes<const N: usize>(text: &str) -> Option<[u8; N]> {
    let body = text.strip_prefix("0x")?.as_bytes();
    if body.len() != N * 2 {
        return None;
    }
    fn nibble(byte: u8) -> Option<u8> {
        match byte {
            b'0'..=b'9' => Some(byte - b'0'),
            b'a'..=b'f' => Some(byte - b'a' + 10),
            b'A'..=b'F' => Some(byte - b'A' + 10),
            _ => None,
        }
    }
    let mut bytes = [0; N];
    for (out, pair) in bytes.iter_mut().zip(body.as_chunks::<2>().0) {
        *out = (nibble(pair[0])? << 4) | nibble(pair[1])?;
    }
    Some(bytes)
}

fn display_hex(bytes: &[u8], f: &mut fmt::Formatter<'_>) -> fmt::Result {
    f.write_str("0x")?;
    for byte in bytes {
        write!(f, "{byte:02x}")?;
    }
    Ok(())
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Account([u8; 20]);

impl Account {
    pub fn parse(text: &str) -> Result<Self, HyperCoreError> {
        hex_bytes(text).map(Self).ok_or(HyperCoreError::InvalidAccount)
    }
}

impl fmt::Display for Account {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        display_hex(&self.0, f)
    }
}

impl Serialize for Account {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.collect_str(self)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Cloid([u8; 16]);

impl Cloid {
    pub fn parse(text: &str) -> Result<Self, HyperCoreError> {
        hex_bytes(text).map(Self).ok_or(HyperCoreError::InvalidCloid)
    }
}

impl fmt::Display for Cloid {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        display_hex(&self.0, f)
    }
}

impl Serialize for Cloid {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.collect_str(self)
    }
}

impl<'de> Deserialize<'de> for Cloid {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let text = String::deserialize(deserializer)?;
        Self::parse(&text).map_err(de::Error::custom)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(untagged)]
pub enum OrderId {
    Oid(u64),
    Cloid(Cloid),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
pub struct TimeRange {
    start_ms: u64,
    end_ms: u64,
}

impl TimeRange {
    pub fn new(start_ms: u64, end_ms: u64) -> Result<Self, HyperCoreError> {
        if start_ms > end_ms {
            return Err(HyperCoreError::InvalidTimeRange);
        }
        Ok(Self { start_ms, end_ms })
    }

    pub fn start_ms(&self) -> u64 {
        self.start_ms
    }

    pub fn end_ms(&self) -> u64 {
        self.end_ms
    }
}

/// The complete permitted wire requests; no arbitrary `type`, dex, or action.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum InfoRequest {
    SpotMeta,
    SpotClearinghouseState { user: Account },
    UserAbstraction { user: Account },
    UserFees { user: Account },
    OpenOrders { user: Account },
    OrderStatus { user: Account, oid: OrderId },
    UserFillsByTime { user: Account, range: TimeRange },
}

impl Serialize for InfoRequest {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let mut map = serializer.serialize_map(None)?;
        let (kind, user) = match self {
            Self::SpotMeta => ("spotMeta", None),
            Self::SpotClearinghouseState { user } => ("spotClearinghouseState", Some(user)),
            Self::UserAbstraction { user } => ("userAbstraction", Some(user)),
            Self::UserFees { user } => ("userFees", Some(user)),
            Self::OpenOrders { user } => ("openOrders", Some(user)),
            Self::OrderStatus { user, .. } => ("orderStatus", Some(user)),
            Self::UserFillsByTime { user, .. } => ("userFillsByTime", Some(user)),
        };
        map.serialize_entry("type", kind)?;
        if let Some(user) = user {
            map.serialize_entry("user", user)?;
        }
        match self {
            Self::OpenOrders { .. } => map.serialize_entry("dex", "")?,
            Self::OrderStatus { oid, .. } => map.serialize_entry("oid", oid)?,
            Self::UserFillsByTime { range, .. } => {
                map.serialize_entry("startTime", &range.start_ms)?;
                map.serialize_entry("endTime", &range.end_ms)?;
                map.serialize_entry("aggregateByTime", &false)?;
            }
            _ => {}
        }
        map.end()
    }
}

/// Exact response text, not order preparation, rounding, or fee enforcement.
/// Coefficient and scale are validated with U256; zero and signed rebates are
/// accepted. Original decimal spelling (including trailing zeros) is retained.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ExactDecimal(String);

impl ExactDecimal {
    pub fn parse(text: &str) -> Result<Self, HyperCoreError> {
        Self::validate(text)?;
        Ok(Self(text.to_owned()))
    }

    fn validate(text: &str) -> Result<(), HyperCoreError> {
        let unsigned = text.strip_prefix('-').unwrap_or(text);
        let (integer, fraction) = match unsigned.split_once('.') {
            Some((integer, fraction)) if !fraction.is_empty() => (integer, fraction),
            Some(_) => return Err(HyperCoreError::InvalidDecimal),
            None => (unsigned, ""),
        };
        if integer.is_empty()
            || (integer.len() > 1 && integer.starts_with('0'))
            || fraction.len() > MAX_DECIMAL_SCALE as usize
            || integer.len() + fraction.len() > 155
        {
            return Err(HyperCoreError::InvalidDecimal);
        }
        let mut coefficient = U256::zero();
        for byte in integer.bytes().chain(fraction.bytes()) {
            if !byte.is_ascii_digit() {
                return Err(HyperCoreError::InvalidDecimal);
            }
            coefficient = coefficient
                .checked_mul(U256::from(10))
                .and_then(|n| n.checked_add(U256::from(byte - b'0')))
                .ok_or(HyperCoreError::InvalidDecimal)?;
        }
        Ok(())
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }

    fn is_negative_nonzero(&self) -> bool {
        self.0.starts_with('-') && self.0.bytes().any(|byte| matches!(byte, b'1'..=b'9'))
    }
}

impl Serialize for ExactDecimal {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&self.0)
    }
}

impl<'de> Deserialize<'de> for ExactDecimal {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let text = String::deserialize(deserializer)?;
        Self::validate(&text).map_err(de::Error::custom)?;
        Ok(Self(text))
    }
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SpotToken {
    name: String,
    index: u32,
    token_id: String,
    sz_decimals: u8,
    wei_decimals: u8,
    is_canonical: bool,
    full_name: Option<String>,
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct SpotPair {
    name: String,
    tokens: [u32; 2],
    index: u32,
    is_canonical: bool,
    action_asset: u32,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct WireToken {
    name: String,
    index: u32,
    token_id: String,
    sz_decimals: u8,
    wei_decimals: u8,
    is_canonical: bool,
    full_name: Option<String>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct WirePair {
    name: String,
    tokens: [u32; 2],
    index: u32,
    is_canonical: bool,
}

#[derive(Deserialize)]
struct WireMetadata {
    tokens: Vec<WireToken>,
    universe: Vec<WirePair>,
}

/// Validated sparse venue indexes, not positions or ticker/asset-backing proof.
#[derive(Clone, Debug, Serialize)]
pub struct SpotMetadata {
    tokens: BTreeMap<u32, SpotToken>,
    universe: BTreeMap<u32, SpotPair>,
    raw_sha256: [u8; 32],
}

impl SpotMetadata {
    pub fn decode(bytes: &[u8]) -> Result<Self, HyperCoreError> {
        let wire: WireMetadata = decode_json(bytes)?;
        let mut tokens = BTreeMap::new();
        let mut token_ids = BTreeSet::new();
        for mut token in wire.tokens {
            let id = hex_bytes::<16>(&token.token_id).ok_or(HyperCoreError::InvalidMetadata)?;
            if token.name.is_empty()
                || token.sz_decimals > 8
                || token.wei_decimals > MAX_DECIMAL_SCALE as u8
                || tokens.contains_key(&token.index)
                || !token_ids.insert(id)
            {
                return Err(HyperCoreError::InvalidMetadata);
            }
            token.token_id.make_ascii_lowercase();
            tokens.insert(token.index, SpotToken {
                name: token.name,
                index: token.index,
                token_id: token.token_id,
                sz_decimals: token.sz_decimals,
                wei_decimals: token.wei_decimals,
                is_canonical: token.is_canonical,
                full_name: token.full_name,
            });
        }
        let mut universe = BTreeMap::new();
        for pair in wire.universe {
            let action_asset = 10_000_u32.checked_add(pair.index)
                .ok_or(HyperCoreError::InvalidMetadata)?;
            // Venue spot names are @pairIndex, with the documented PURR/USDC
            // pair-zero exception. Arbitrary tickers would alias perpetuals.
            let correct_coin = if pair.name == "PURR/USDC" {
                pair.index == 0
            } else {
                pair.name.strip_prefix('@').is_some_and(|index| {
                    !index.is_empty()
                        && (index == "0" || !index.starts_with('0'))
                        && index.parse::<u32>() == Ok(pair.index)
                        && index.bytes().all(|byte| byte.is_ascii_digit())
                })
            };
            if !correct_coin
                || pair.tokens[0] == pair.tokens[1]
                || !tokens.contains_key(&pair.tokens[0])
                || !tokens.contains_key(&pair.tokens[1])
                || universe.contains_key(&pair.index)
            {
                return Err(HyperCoreError::InvalidMetadata);
            }
            universe.insert(pair.index, SpotPair {
                name: pair.name,
                tokens: pair.tokens,
                index: pair.index,
                is_canonical: pair.is_canonical,
                action_asset,
            });
        }
        Ok(Self { tokens, universe, raw_sha256: Sha256::digest(bytes).into() })
    }

    pub fn select_market(
        &self,
        pair_index: u32,
        expected_base_token_id: &str,
        expected_quote_token_id: &str,
    ) -> Result<SpotMarket, HyperCoreError> {
        let pair = self.universe.get(&pair_index).ok_or(HyperCoreError::AssetMismatch)?;
        let base = &self.tokens[&pair.tokens[0]];
        let quote = &self.tokens[&pair.tokens[1]];
        if hex_bytes::<16>(expected_base_token_id).is_none()
            || hex_bytes::<16>(expected_quote_token_id).is_none()
            || !base.token_id.eq_ignore_ascii_case(expected_base_token_id)
            || !quote.token_id.eq_ignore_ascii_case(expected_quote_token_id)
        {
            return Err(HyperCoreError::AssetMismatch);
        }
        Ok(SpotMarket {
            pair: pair.clone(),
            base: base.clone(),
            quote: quote.clone(),
            metadata_sha256: self.raw_sha256,
        })
    }

    pub fn raw_sha256(&self) -> [u8; 32] {
        self.raw_sha256
    }
}

/// Exact selected spot identity; canonical flags remain unverified venue data.
#[derive(Clone, Debug, Serialize)]
pub struct SpotMarket {
    pair: SpotPair,
    base: SpotToken,
    quote: SpotToken,
    metadata_sha256: [u8; 32],
}

impl SpotMarket {
    pub fn action_asset(&self) -> u32 {
        self.pair.action_asset
    }

    pub fn coin(&self) -> &str {
        &self.pair.name
    }

    pub fn pair_index(&self) -> u32 {
        self.pair.index
    }

    pub fn base_index(&self) -> u32 {
        self.base.index
    }

    pub fn quote_index(&self) -> u32 {
        self.quote.index
    }

    pub fn size_decimals(&self) -> u8 {
        self.base.sz_decimals
    }

    pub fn base_token_id(&self) -> &str {
        &self.base.token_id
    }

    pub fn quote_token_id(&self) -> &str {
        &self.quote.token_id
    }

    pub fn metadata_sha256(&self) -> [u8; 32] {
        self.metadata_sha256
    }
}

fn decode_json<T: de::DeserializeOwned>(bytes: &[u8]) -> Result<T, HyperCoreError> {
    if bytes.len() > MAX_INFO_RESPONSE_BYTES {
        return Err(HyperCoreError::ResponseTooLarge);
    }
    serde_json::from_slice(bytes).map_err(|_| HyperCoreError::MalformedResponse)
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct SpotClearinghouseState {
    pub balances: Vec<SpotBalance>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SpotBalance {
    pub coin: String,
    pub token: u32,
    pub hold: ExactDecimal,
    pub total: ExactDecimal,
    pub entry_ntl: ExactDecimal,
}

/// Every mode is preserved. No mode here authorizes an isolated/no-leverage claim.
#[derive(Clone, Debug, Serialize)]
pub struct AccountMode(String);

impl AccountMode {
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct UserFees {
    pub user_spot_cross_rate: ExactDecimal,
    pub user_spot_add_rate: ExactDecimal,
    pub active_referral_discount: ExactDecimal,
    pub fee_schedule: SpotFeeSchedule,
}

/// Only consumed spot/base referral rates; the complete source bytes are retained
/// by ApiObservation. None of these observations is an enforced trading fee cap.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SpotFeeSchedule {
    pub spot_cross: ExactDecimal,
    pub spot_add: ExactDecimal,
    pub referral_discount: ExactDecimal,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Deserialize, Serialize)]
pub enum Side {
    #[serde(rename = "B")]
    Buy,
    #[serde(rename = "A")]
    Sell,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
pub enum ReadScope {
    SpotAndFirstDexPerpetuals,
    SpotAndPerpetuals,
}

/// This endpoint mixes spot and first-dex perpetuals; no spot-only provenance.
#[derive(Clone, Debug, Serialize)]
pub struct OpenOrders {
    pub orders: Vec<OpenOrder>,
    scope: ReadScope,
}

impl OpenOrders {
    pub fn scope(&self) -> ReadScope {
        self.scope
    }

    pub fn for_market<'a>(&'a self, market: &'a SpotMarket) -> impl Iterator<Item = &'a OpenOrder> + 'a {
        self.orders.iter().filter(move |order| order.coin == market.coin())
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct OpenOrder {
    pub coin: String,
    pub limit_px: ExactDecimal,
    pub oid: u64,
    pub side: Side,
    pub sz: ExactDecimal,
    pub timestamp: u64,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct StatusOrder {
    #[serde(flatten)]
    pub order: OpenOrder,
    pub orig_sz: ExactDecimal,
    pub tif: Option<String>,
    pub cloid: Option<Cloid>,
}

/// Status strings are venue history, including future or perpetual-specific
/// states. Neither unknownOid nor any returned status releases reservations.
#[derive(Clone, Debug, Serialize)]
pub enum OrderStatus {
    UnknownOid,
    Order { order: StatusOrder, status: String, status_timestamp: u64 },
}

#[derive(Deserialize)]
#[serde(tag = "status")]
enum WireOrderStatus {
    #[serde(rename = "unknownOid")]
    UnknownOid,
    #[serde(rename = "order")]
    Order { order: WireStatusRecord },
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct WireStatusRecord {
    order: StatusOrder,
    status: String,
    status_timestamp: u64,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Fill {
    pub coin: String,
    pub px: ExactDecimal,
    pub sz: ExactDecimal,
    pub side: Side,
    pub time: u64,
    pub oid: u64,
    pub tid: u64,
    /// Vendor field only: not an EVM receipt, signing hash, or cloid.
    pub hash: String,
    pub crossed: bool,
    /// Total signed fee, already inclusive of builderFee; do not add them.
    pub fee: ExactDecimal,
    pub fee_token: String,
    pub builder_fee: Option<ExactDecimal>,
    pub start_position: ExactDecimal,
    pub dir: String,
    pub closed_pnl: ExactDecimal,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
pub enum CoverageCompleteness {
    Incomplete,
}

#[derive(Clone, Debug, Serialize)]
pub struct FillCoverage {
    pub requested_range: TimeRange,
    pub returned: usize,
    pub per_response_limit: usize,
    pub retained_latest_limit: usize,
    pub saturated: bool,
    pub completeness: CoverageCompleteness,
}

/// Latest-retained-history, possibly capped and mixed spot/perpetual fills.
/// An empty or unsaturated response is still not complete financial history.
#[derive(Clone, Debug, Serialize)]
pub struct FillsByTime {
    pub fills: Vec<Fill>,
    pub coverage: FillCoverage,
    scope: ReadScope,
}

impl FillsByTime {
    pub fn scope(&self) -> ReadScope {
        self.scope
    }

    pub fn for_market<'a>(&'a self, market: &'a SpotMarket) -> impl Iterator<Item = &'a Fill> + 'a {
        self.fills.iter().filter(move |fill| fill.coin == market.coin())
    }
}

/// Every payload here is an unverified info observation, never financial truth.
#[derive(Clone, Debug, Serialize)]
#[serde(tag = "requestType", content = "observation", rename_all = "camelCase")]
pub enum InfoResponse {
    SpotMeta(SpotMetadata),
    SpotClearinghouseState(SpotClearinghouseState),
    UserAbstraction(AccountMode),
    UserFees(UserFees),
    OpenOrders(OpenOrders),
    OrderStatus(OrderStatus),
    UserFillsByTime(FillsByTime),
}

impl InfoResponse {
    /// Offline/native consumers use the very same byte bound, consumed-field
    /// validators, and request-identity/range checks as network acquisition.
    pub fn decode(request: &InfoRequest, bytes: &[u8]) -> Result<Self, HyperCoreError> {
        match request {
            InfoRequest::SpotMeta => Ok(Self::SpotMeta(SpotMetadata::decode(bytes)?)),
            InfoRequest::SpotClearinghouseState { .. } => {
                let state: SpotClearinghouseState = decode_json(bytes)?;
                let mut indexes = BTreeSet::new();
                if state.balances.iter().any(|balance| {
                    balance.coin.is_empty() || !indexes.insert(balance.token)
                        || balance.hold.is_negative_nonzero()
                        || balance.total.is_negative_nonzero()
                }) {
                    return Err(HyperCoreError::MalformedResponse);
                }
                Ok(Self::SpotClearinghouseState(state))
            }
            InfoRequest::UserAbstraction { .. } => {
                let mode: String = decode_json(bytes)?;
                if mode.is_empty() {
                    return Err(HyperCoreError::MalformedResponse);
                }
                Ok(Self::UserAbstraction(AccountMode(mode)))
            }
            InfoRequest::UserFees { .. } => Ok(Self::UserFees(decode_json(bytes)?)),
            InfoRequest::OpenOrders { .. } => {
                let orders: Vec<OpenOrder> = decode_json(bytes)?;
                let mut identities = BTreeSet::new();
                if orders.iter().any(|order| {
                    order.coin.is_empty() || !identities.insert(order.oid)
                        || order.limit_px.is_negative_nonzero() || order.sz.is_negative_nonzero()
                }) {
                    return Err(HyperCoreError::MalformedResponse);
                }
                Ok(Self::OpenOrders(OpenOrders {
                    orders,
                    scope: ReadScope::SpotAndFirstDexPerpetuals,
                }))
            }
            InfoRequest::OrderStatus { oid, .. } => {
                let status = match decode_json::<WireOrderStatus>(bytes)? {
                    WireOrderStatus::UnknownOid => OrderStatus::UnknownOid,
                    WireOrderStatus::Order { order: record } => {
                        if record.status.is_empty() || record.order.order.coin.is_empty()
                            || record.order.order.limit_px.is_negative_nonzero()
                            || record.order.order.sz.is_negative_nonzero()
                            || record.order.orig_sz.is_negative_nonzero()
                        {
                            return Err(HyperCoreError::MalformedResponse);
                        }
                        let matches = match oid {
                            OrderId::Oid(oid) => *oid == record.order.order.oid,
                            OrderId::Cloid(cloid) => Some(*cloid) == record.order.cloid,
                        };
                        if !matches {
                            return Err(HyperCoreError::RequestMismatch);
                        }
                        OrderStatus::Order {
                            order: record.order,
                            status: record.status,
                            status_timestamp: record.status_timestamp,
                        }
                    }
                };
                Ok(Self::OrderStatus(status))
            }
            InfoRequest::UserFillsByTime { range, .. } => {
                let fills: Vec<Fill> = decode_json(bytes)?;
                if fills.len() > MAX_FILLS || fills.iter().any(|fill| {
                    fill.coin.is_empty() || fill.fee_token.is_empty()
                        || fill.dir.is_empty() || hex_bytes::<32>(&fill.hash).is_none()
                        || fill.px.is_negative_nonzero() || fill.sz.is_negative_nonzero()
                }) {
                    return Err(HyperCoreError::MalformedResponse);
                }
                if fills.iter().any(|fill| fill.time < range.start_ms || fill.time > range.end_ms) {
                    return Err(HyperCoreError::RequestMismatch);
                }
                let coverage = FillCoverage {
                    requested_range: *range,
                    returned: fills.len(),
                    per_response_limit: MAX_FILLS,
                    retained_latest_limit: RETAINED_FILLS,
                    saturated: fills.len() == MAX_FILLS,
                    completeness: CoverageCompleteness::Incomplete,
                };
                Ok(Self::UserFillsByTime(FillsByTime {
                    fills,
                    coverage,
                    scope: ReadScope::SpotAndPerpetuals,
                }))
            }
        }
    }
}

/// Owned exact source and typed consumed payload. There is deliberately no
/// public constructor: provenance is populated only after actual acquisition.
#[derive(Debug)]
pub struct ApiObservation {
    network: Network,
    request: InfoRequest,
    payload: InfoResponse,
    raw_bytes: Vec<u8>,
    raw_sha256: [u8; 32],
    acquired_at_unix_ms: u64,
}

impl ApiObservation {
    pub fn network(&self) -> Network {
        self.network
    }

    pub fn endpoint(&self) -> &'static str {
        TESTNET_INFO_ENDPOINT
    }

    pub fn request(&self) -> &InfoRequest {
        &self.request
    }

    pub fn payload(&self) -> &InfoResponse {
        &self.payload
    }

    /// Display/provenance only: additional fields are not typed financial facts.
    pub fn raw_bytes(&self) -> &[u8] {
        &self.raw_bytes
    }

    pub fn raw_sha256(&self) -> [u8; 32] {
        self.raw_sha256
    }

    /// Local wall-clock metadata, never venue time, finality, or a freshness proof.
    pub fn acquired_at_unix_ms(&self) -> u64 {
        self.acquired_at_unix_ms
    }
}

/// One concrete client: explicit testnet, HTTPS, no redirect/proxy/retry or
/// fallback, 10s connect / 30s total timeout including body consumption.
pub struct HyperCoreInfoClient {
    network: Network,
    client: reqwest::Client,
}

impl HyperCoreInfoClient {
    pub fn new(network: Network) -> Result<Self, HyperCoreError> {
        let client = reqwest::Client::builder()
            .https_only(true)
            .redirect(reqwest::redirect::Policy::none())
            .retry(reqwest::retry::never())
            // Hyper's legacy pool can retry an unstarted canceled request on a
            // reused connection independently of reqwest's retry policy.
            .pool_max_idle_per_host(0)
            .no_proxy()
            .no_gzip()
            .no_brotli()
            .no_zstd()
            .no_deflate()
            .connect_timeout(Duration::from_secs(10))
            .timeout(Duration::from_secs(30))
            .build()
            .map_err(|_| HyperCoreError::ClientConfiguration)?;
        Ok(Self { network, client })
    }

    pub async fn request(&self, request: InfoRequest) -> Result<ApiObservation, HyperCoreError> {
        let mut response = self.client.post(TESTNET_INFO_ENDPOINT)
            .json(&request)
            .send().await.map_err(transport_error)?;
        if !response.status().is_success() {
            return Err(HyperCoreError::HttpStatus(response.status().as_u16()));
        }
        if response.content_length().is_some_and(|length| length > MAX_INFO_RESPONSE_BYTES as u64) {
            return Err(HyperCoreError::ResponseTooLarge);
        }
        // Allocate once using the advertised length (already bounded), or the
        // hard maximum for chunked input. Never retain bytes beyond the limit.
        let capacity = response.content_length()
            .map_or(MAX_INFO_RESPONSE_BYTES, |length| length as usize);
        let mut bytes = Vec::with_capacity(capacity);
        while let Some(chunk) = response.chunk().await.map_err(transport_error)? {
            if chunk.len() > MAX_INFO_RESPONSE_BYTES - bytes.len() {
                return Err(HyperCoreError::ResponseTooLarge);
            }
            bytes.extend_from_slice(&chunk);
        }
        let payload = InfoResponse::decode(&request, &bytes)?;
        let raw_sha256 = match &payload {
            InfoResponse::SpotMeta(metadata) => metadata.raw_sha256(),
            _ => Sha256::digest(&bytes).into(),
        };
        let acquired_at_unix_ms = u64::try_from(SystemTime::now()
            .duration_since(UNIX_EPOCH).map_err(|_| HyperCoreError::Clock)?
            .as_millis()).map_err(|_| HyperCoreError::Clock)?;
        Ok(ApiObservation {
            network: self.network,
            request,
            payload,
            raw_bytes: bytes,
            raw_sha256,
            acquired_at_unix_ms,
        })
    }
}

fn transport_error(error: reqwest::Error) -> HyperCoreError {
    if error.is_timeout() {
        HyperCoreError::Timeout
    } else {
        HyperCoreError::Transport
    }
}
