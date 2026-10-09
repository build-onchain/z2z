//! Explicit external venue information and offline proposals. No signer or submission.
use clap::{Args, Parser, Subcommand, ValueEnum, error::ErrorKind};
use serde::{Deserialize, de::DeserializeOwned};
use std::{ffi::OsString, fmt, io::{Read, Write}, path::PathBuf, process::ExitCode};
use ziquid_chains::hypercore::{Account, Cloid, HyperCoreError, HyperCoreInfoClient, InfoRequest, Network, OrderId, SpotMetadata, TimeRange};
use ziquid_chains::hypercore::{Side, spot::{FeeCap, SpotCancelIntent, SpotOrderIntent, SpotPreparationError, SpotTif, prepare_spot_cancel, prepare_spot_order}};
const MAX_METADATA_BYTES: usize = 2 * 1024 * 1024;
const MAX_INTENT_BYTES: usize = 64 * 1024;
#[derive(Parser)]
#[command(name="ziquid hypercore", version, about="Explicit testnet information and offline spot proposals; no signing or exchange submission")]
struct Cli { #[command(subcommand)] command: Command }
#[derive(Subcommand)]
enum Command {
    InspectMeta {
        #[arg(long)] file: PathBuf,
        #[arg(long)] pair_index: u32,
        #[arg(long)] base_token_id: String,
        #[arg(long)] quote_token_id: String,
    },
    Info {
        #[command(flatten)] options: InfoOptions,
    },
    PrepareOrder {
        #[arg(long)] metadata: PathBuf,
        #[arg(long)] intent: PathBuf,
    },
    PrepareCancel {
        #[arg(long)] metadata: PathBuf,
        #[arg(long)] intent: PathBuf,
    },
}

#[derive(Clone, Copy, ValueEnum)]
enum InfoNetwork { Testnet }

#[derive(Clone, Copy, ValueEnum)]
enum RequestKind {
    SpotMeta,
    SpotBalances,
    AccountMode,
    UserFees,
    OpenOrders,
    OrderStatus,
    FillsByTime,
}

#[derive(Args)]
struct InfoOptions {
    #[arg(long, value_enum)] network: InfoNetwork,
    #[arg(long, value_enum)] request: RequestKind,
    /// Required for all reads except spot-meta; never printed in diagnostics.
    #[arg(long)] account: Option<String>,
    /// Exact numeric order ID; order-status only, mutually exclusive with cloid.
    #[arg(long, conflicts_with="cloid")] oid: Option<u64>,
    /// Exact 16-byte client order ID; order-status only.
    #[arg(long)] cloid: Option<String>,
    /// Explicit inclusive start time; fills-by-time only.
    #[arg(long)] start_ms: Option<u64>,
    /// Explicit inclusive end time; fills-by-time only.
    #[arg(long)] end_ms: Option<u64>,
}

impl InfoOptions {
    fn into_request(self) -> Result<(Network, InfoRequest), CliError> {
        let network = match self.network { InfoNetwork::Testnet => Network::Testnet };
        if matches!(self.request, RequestKind::SpotMeta) {
            if self.account.is_some() || self.oid.is_some() || self.cloid.is_some()
                || self.start_ms.is_some() || self.end_ms.is_some() {
                return Err(CliError::InvalidSelectors);
            }
            return Ok((network, InfoRequest::SpotMeta));
        }
        if !matches!(self.request, RequestKind::OrderStatus)
            && (self.oid.is_some() || self.cloid.is_some()) {
            return Err(CliError::InvalidSelectors);
        }
        if !matches!(self.request, RequestKind::FillsByTime)
            && (self.start_ms.is_some() || self.end_ms.is_some()) {
            return Err(CliError::InvalidSelectors);
        }
        let user = Account::parse(self.account.as_deref().ok_or(CliError::InvalidSelectors)?)
            .map_err(|_| CliError::InvalidAccount)?;
        let request = match self.request {
            RequestKind::SpotMeta => unreachable!("spot-meta handled before account parsing"),
            RequestKind::SpotBalances => InfoRequest::SpotClearinghouseState { user },
            RequestKind::AccountMode => InfoRequest::UserAbstraction { user },
            RequestKind::UserFees => InfoRequest::UserFees { user },
            RequestKind::OpenOrders => InfoRequest::OpenOrders { user },
            RequestKind::OrderStatus => {
                let oid = match (self.oid, self.cloid) {
                    (Some(oid), None) => OrderId::Oid(oid),
                    (None, Some(cloid)) => OrderId::Cloid(Cloid::parse(&cloid).map_err(|_| CliError::InvalidCloid)?),
                    _ => return Err(CliError::InvalidSelectors),
                };
                InfoRequest::OrderStatus { user, oid }
            }
            RequestKind::FillsByTime => {
                let range = TimeRange::new(
                    self.start_ms.ok_or(CliError::InvalidSelectors)?,
                    self.end_ms.ok_or(CliError::InvalidSelectors)?,
                ).map_err(|_| CliError::InvalidTimeRange)?;
                InfoRequest::UserFillsByTime { user, range }
            }
        };
        Ok((network, request))
    }
}

fn proposal_network<'de, D: serde::Deserializer<'de>>(deserializer: D) -> Result<Network, D::Error> {
    match String::deserialize(deserializer)?.as_str() {
        "testnet" => Ok(Network::Testnet),
        _ => Err(serde::de::Error::custom("invalid proposal network")),
    }
}

fn proposal_side<'de, D: serde::Deserializer<'de>>(deserializer: D) -> Result<Side, D::Error> {
    match String::deserialize(deserializer)?.as_str() {
        "buy" => Ok(Side::Buy),
        "sell" => Ok(Side::Sell),
        _ => Err(serde::de::Error::custom("invalid proposal side")),
    }
}

fn proposal_tif<'de, D: serde::Deserializer<'de>>(deserializer: D) -> Result<SpotTif, D::Error> {
    match String::deserialize(deserializer)?.as_str() {
        "Gtc" => Ok(SpotTif::Gtc),
        "Alo" => Ok(SpotTif::Alo),
        "Ioc" => Ok(SpotTif::Ioc),
        _ => Err(serde::de::Error::custom("invalid proposal time in force")),
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct OrderConfig {
    #[serde(deserialize_with = "proposal_network")]
    network: Network,
    account: String,
    nonce: u64,
    expires_after_ms: u64,
    pair_index: u32,
    base_token_id: String,
    quote_token_id: String,
    cloid: String,
    #[serde(deserialize_with = "proposal_side")]
    side: Side,
    size: String,
    limit_price: String,
    #[serde(deserialize_with = "proposal_tif")]
    tif: SpotTif,
    fee_cap: FeeCap,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct CancelConfig {
    #[serde(deserialize_with = "proposal_network")]
    network: Network,
    account: String,
    nonce: u64,
    expires_after_ms: u64,
    pair_index: u32,
    base_token_id: String,
    quote_token_id: String,
    #[serde(default, deserialize_with = "present_selector")]
    oid: Option<u64>,
    #[serde(default, deserialize_with = "present_selector")]
    cloid: Option<String>,
}

// A provided null is not an absent selector, and must not bypass exclusivity.
fn present_selector<'de, D, T>(deserializer: D) -> Result<Option<T>, D::Error>
where D: serde::Deserializer<'de>, T: Deserialize<'de> {
    T::deserialize(deserializer).map(Some)
}

fn read_intent<T: DeserializeOwned>(path: PathBuf) -> Result<T, CliError> {
    let mut bytes = Vec::new();
    std::fs::File::open(path).map_err(|_| CliError::IntentFileUnavailable)?
        .take((MAX_INTENT_BYTES + 1) as u64).read_to_end(&mut bytes)
        .map_err(|_| CliError::IntentFileUnreadable)?;
    if bytes.len() > MAX_INTENT_BYTES { return Err(CliError::IntentTooLarge); }
    serde_json::from_slice(&bytes).map_err(|_| CliError::InvalidIntent)
}

fn read_metadata(path: PathBuf) -> Result<SpotMetadata, CliError> {
    let mut bytes = Vec::new();
    std::fs::File::open(path).map_err(|_| CliError::MetadataFileUnavailable)?
        .take((MAX_METADATA_BYTES + 1) as u64).read_to_end(&mut bytes)
        .map_err(|_| CliError::MetadataFileUnreadable)?;
    if bytes.len() > MAX_METADATA_BYTES { return Err(HyperCoreError::ResponseTooLarge.into()); }
    Ok(SpotMetadata::decode(&bytes)?)
}

#[derive(Debug)]
enum CliError {
    InvalidSelectors,
    InvalidAccount,
    InvalidCloid,
    InvalidTimeRange,
    MetadataFileUnavailable,
    MetadataFileUnreadable,
    RuntimeUnavailable,
    IntentFileUnavailable,
    IntentFileUnreadable,
    IntentTooLarge,
    InvalidIntent,
    ProposalEncoding,
    Preparation(SpotPreparationError),
    Info(HyperCoreError),
}

impl CliError {
    fn exit_code(&self) -> ExitCode {
        match self {
            Self::InvalidSelectors | Self::InvalidAccount | Self::InvalidCloid | Self::InvalidTimeRange => ExitCode::from(2),
            _ => ExitCode::FAILURE,
        }
    }
}

impl fmt::Display for CliError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::InvalidSelectors => "invalid HyperCore info request selectors",
            Self::InvalidAccount => "invalid HyperCore account identity",
            Self::InvalidCloid => "invalid HyperCore client order identity",
            Self::InvalidTimeRange => "invalid HyperCore time range",
            Self::MetadataFileUnavailable => "metadata file unavailable",
            Self::MetadataFileUnreadable => "metadata file unreadable",
            Self::RuntimeUnavailable => "HyperCore info runtime unavailable",
            Self::IntentFileUnavailable => "intent file unavailable",
            Self::IntentFileUnreadable => "intent file unreadable",
            Self::IntentTooLarge => "HyperCore intent exceeds byte limit",
            Self::InvalidIntent => "invalid HyperCore spot intent configuration",
            Self::ProposalEncoding => "HyperCore spot proposal encoding failed",
            Self::Preparation(error) => return fmt::Display::fmt(error, f),
            Self::Info(HyperCoreError::HttpStatus(_)) => "HyperCore info HTTP request rejected",
            Self::Info(error) => return fmt::Display::fmt(error, f),
        })
    }
}

impl From<HyperCoreError> for CliError {
    fn from(error: HyperCoreError) -> Self { Self::Info(error) }
}
pub fn run_cli(arguments: impl IntoIterator<Item=OsString>) -> ExitCode {
    let cli = match Cli::try_parse_from(std::iter::once(OsString::from("ziquid hypercore")).chain(arguments)) {
        Ok(cli)=>cli,
        Err(error)=>{
            if matches!(error.kind(), ErrorKind::DisplayHelp | ErrorKind::DisplayVersion) {
                return if error.print().is_ok() { ExitCode::SUCCESS } else { ExitCode::FAILURE };
            }
            eprintln!("invalid HyperCore command arguments");
            return ExitCode::from(2);
        }
    };
    match execute(cli) {
        Ok(output)=>{
            let stdout=std::io::stdout();let mut locked=stdout.lock();
            if serde_json::to_writer(&mut locked,&output).is_err() || locked.write_all(b"\n").is_err(){return ExitCode::FAILURE;}
            ExitCode::SUCCESS
        }
        Err(error)=>{eprintln!("{error}");error.exit_code()}
    }
}
fn execute(cli: Cli) -> Result<serde_json::Value, CliError> {
    match cli.command {
        Command::InspectMeta{file,pair_index,base_token_id,quote_token_id}=>{
            let meta=read_metadata(file)?;
            let market=meta.select_market(pair_index,&base_token_id,&quote_token_id)?;
            Ok(serde_json::json!({"source":"caller_file","source_validity":"UNVERIFIED","signing":false,"exchange_submission":false,"market":{"pair_index":market.pair_index(),"action_asset":market.action_asset(),"coin":market.coin(),"base_index":market.base_index(),"quote_index":market.quote_index(),"base_token_id":market.base_token_id(),"quote_token_id":market.quote_token_id(),"size_decimals":market.size_decimals()}}))
        }
        Command::PrepareOrder { metadata, intent } => {
            let config: OrderConfig = read_intent(intent)?;
            let meta = read_metadata(metadata)?;
            let market = meta.select_market(config.pair_index, &config.base_token_id, &config.quote_token_id)?;
            let intent = SpotOrderIntent {
                network: config.network,
                account: Account::parse(&config.account).map_err(|_| CliError::InvalidIntent)?,
                nonce: config.nonce,
                expires_after_ms: config.expires_after_ms,
                cloid: Cloid::parse(&config.cloid).map_err(|_| CliError::InvalidIntent)?,
                side: config.side,
                size: config.size,
                limit_price: config.limit_price,
                tif: config.tif,
                fee_cap: config.fee_cap,
            };
            let prepared = prepare_spot_order(&market, &intent).map_err(CliError::Preparation)?;
            // Preserve the ordered action byte string; this Value is display only.
            serde_json::to_value(prepared).map_err(|_| CliError::ProposalEncoding)
        }
        Command::PrepareCancel { metadata, intent } => {
            let config: CancelConfig = read_intent(intent)?;
            let order = match (config.oid, config.cloid) {
                (Some(oid), None) => OrderId::Oid(oid),
                (None, Some(cloid)) => OrderId::Cloid(Cloid::parse(&cloid).map_err(|_| CliError::InvalidIntent)?),
                _ => return Err(CliError::InvalidIntent),
            };
            let meta = read_metadata(metadata)?;
            let market = meta.select_market(config.pair_index, &config.base_token_id, &config.quote_token_id)?;
            let intent = SpotCancelIntent {
                network: config.network,
                account: Account::parse(&config.account).map_err(|_| CliError::InvalidIntent)?,
                nonce: config.nonce,
                expires_after_ms: config.expires_after_ms,
                order,
            };
            let prepared = prepare_spot_cancel(&market, &intent).map_err(CliError::Preparation)?;
            serde_json::to_value(prepared).map_err(|_| CliError::ProposalEncoding)
        }
        Command::Info{options}=>{
            let (network, request) = options.into_request()?;
            let runtime=tokio::runtime::Builder::new_current_thread().enable_all().build()
                .map_err(|_|CliError::RuntimeUnavailable)?;
            let observed=runtime.block_on(async {HyperCoreInfoClient::new(network)?.request(request).await})?;
            Ok(serde_json::json!({"network":"testnet","endpoint":observed.endpoint(),"source_validity":"UNVERIFIED","signing":false,"exchange_submission":false,"acquired_at_unix_ms":observed.acquired_at_unix_ms(),"raw_sha256":observed.raw_sha256(),"request":observed.request(),"response":observed.payload()}))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ziquid_chains::hypercore::{HyperCoreError, InfoResponse};

    fn selected_request(selectors: &[&str]) -> InfoRequest {
        let cli = Cli::try_parse_from(
            ["ziquid hypercore", "info", "--network", "testnet"]
                .into_iter().chain(selectors.iter().copied()),
        ).unwrap();
        let Command::Info { options } = cli.command else { panic!("info command required") };
        options.into_request().unwrap().1
    }

    #[test]
    fn order_selector_binds_response_identity_not_another_order() {
        let response = br#"{"status":"order","order":{"order":{"coin":"@0","side":"B","limitPx":"1","sz":"1","oid":41,"timestamp":1,"origSz":"1","cloid":"0x00112233445566778899aabbccddeeff"},"status":"open","statusTimestamp":1}}"#;
        for (selector, selected, other) in [
            ("--oid", "41", "42"),
            ("--cloid", "0x00112233445566778899aabbccddeeff", "0x00112233445566778899aabbccddee00"),
        ] {
            let correct = selected_request(&["--request", "order-status", "--account", "0x0000000000000000000000000000000000000000", selector, selected]);
            assert!(InfoResponse::decode(&correct, response).is_ok());
            let incorrect = selected_request(&["--request", "order-status", "--account", "0x0000000000000000000000000000000000000000", selector, other]);
            assert!(matches!(InfoResponse::decode(&incorrect, response), Err(HyperCoreError::RequestMismatch)));
        }
    }

    #[test]
    fn explicit_fill_interval_rejects_response_outside_selected_range() {
        let response = br#"[{"coin":"@0","px":"1","sz":"1","side":"B","time":15,"startPosition":"0","dir":"Open Long","closedPnl":"0","hash":"0x0000000000000000000000000000000000000000000000000000000000000000","oid":41,"crossed":false,"fee":"0","tid":1,"feeToken":"USDC"}]"#;
        for (start, end, accepted) in [("10", "20", true), ("16", "20", false), ("10", "14", false)] {
            let request = selected_request(&["--request", "fills-by-time", "--account", "0x0000000000000000000000000000000000000000", "--start-ms", start, "--end-ms", end]);
            let decoded = InfoResponse::decode(&request, response);
            if accepted {
                assert!(decoded.is_ok());
            } else {
                assert!(matches!(decoded, Err(HyperCoreError::RequestMismatch)));
            }
        }
    }
}
