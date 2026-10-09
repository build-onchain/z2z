//! Sparse venue metadata indexes are identities, not array positions/tickers.
use ziquid_chains::hypercore::{HyperCoreError, SpotMetadata};
const META: &[u8] = br#"{"tokens":[{"name":"QUOTE","szDecimals":8,"weiDecimals":8,"index":9,"tokenId":"0x99999999999999999999999999999999","isCanonical":true},{"name":"BASE","szDecimals":2,"weiDecimals":8,"index":3,"tokenId":"0x33333333333333333333333333333333","isCanonical":true}],"universe":[{"name":"@7","tokens":[3,9],"index":7,"isCanonical":true}]}"#;
#[test]
fn selects_sparse_spot_indexes_and_binds_both_token_identities() {
    let meta = SpotMetadata::decode(META).unwrap();
    let market = meta.select_market(7,"0x33333333333333333333333333333333","0x99999999999999999999999999999999").unwrap();
    assert_eq!(market.action_asset(),10_007);
    assert_eq!(market.coin(),"@7");
    assert_eq!(market.base_index(),3);
    assert_eq!(market.quote_index(),9);
    assert_eq!(market.size_decimals(),2);
    assert_eq!(meta.select_market(7,"0x99999999999999999999999999999999","0x33333333333333333333333333333333").unwrap_err(),HyperCoreError::AssetMismatch);
}

use ziquid_chains::hypercore::{
    Account, Cloid, CoverageCompleteness, ExactDecimal, InfoRequest, InfoResponse, OrderId,
    OrderStatus, ReadScope, Side, TimeRange, MAX_INFO_RESPONSE_BYTES,
};
use serde_json::{Value, json};

const ACCOUNT: &str = "0x1111111111111111111111111111111111111111";
const CLOID: &str = "0x0000000000000000000000000000000a";
const ACQUIRED_META: &[u8] = include_bytes!("fixtures/hypercore-testnet-spot-meta.json");

fn metadata_value() -> Value {
    serde_json::from_slice(META).unwrap()
}

fn decode_metadata(value: &Value) -> Result<SpotMetadata, HyperCoreError> {
    SpotMetadata::decode(&serde_json::to_vec(value).unwrap())
}

fn account() -> Account {
    Account::parse(ACCOUNT).unwrap()
}

fn fills_request(start: u64, end: u64) -> InfoRequest {
    InfoRequest::UserFillsByTime {
        user: account(),
        range: TimeRange::new(start, end).unwrap(),
    }
}

fn fill(time: u64) -> Value {
    json!({
        "coin":"@7", "px":"18.62041381", "sz":"43.84", "side":"A", "time":time,
        "startPosition":"10659.65434798", "dir":"Sell", "closedPnl":"-12.5",
        "hash":"0x2222138cc516e3fe746c0411dd733f02e60086f43205af2ae37c93f6a792430b",
        "oid":59071663721_u64, "crossed":true, "fee":"-0.0001", "builderFee":"0.00002",
        "tid":907359904431134_u64, "feeToken":"PURR", "extraFutureField":true
    })
}

#[test]
fn acquired_testnet_pair_binds_real_ids_and_ignores_unconsumed_contract_objects() {
    let meta = SpotMetadata::decode(ACQUIRED_META).unwrap();
    let market = meta.select_market(
        0,
        "0xc4bf3f870c0e9465323c0b6ed28096c2",
        "0xeb62eee3685fc4c43992febcd9e75443",
    ).unwrap();
    assert_eq!(market.coin(), "PURR/USDC");
    assert_eq!(market.action_asset(), 10_000);
    assert_eq!(market.base_index(), 1);
    assert_eq!(market.quote_index(), 0);
    assert_eq!(market.size_decimals(), 0);
    assert_eq!(market.base_token_id(), "0xc4bf3f870c0e9465323c0b6ed28096c2");
    assert_eq!(market.quote_token_id(), "0xeb62eee3685fc4c43992febcd9e75443");
    assert_eq!(meta.select_market(0, "PURR", "USDC").unwrap_err(), HyperCoreError::AssetMismatch);
}

#[test]
fn rejects_duplicate_or_malformed_token_and_pair_identities() {
    let mut cases = Vec::new();
    let mut value = metadata_value();
    value["tokens"][1]["index"] = json!(9);
    cases.push(value);
    let mut value = metadata_value();
    value["tokens"][1]["tokenId"] = json!("0x99999999999999999999999999999999");
    cases.push(value);
    for invalid_id in ["0x33", "0xgg333333333333333333333333333333", "33333333333333333333333333333333"] {
        let mut value = metadata_value();
        value["tokens"][1]["tokenId"] = json!(invalid_id);
        cases.push(value);
    }
    let mut value = metadata_value();
    value["universe"][0]["tokens"] = json!([3, 20]);
    cases.push(value);
    let mut value = metadata_value();
    value["universe"][0]["tokens"] = json!([3, 3]);
    cases.push(value);
    let mut value = metadata_value();
    let duplicate_pair = value["universe"][0].clone();
    value["universe"].as_array_mut().unwrap().push(duplicate_pair);
    cases.push(value);
    let mut value = metadata_value();
    value["tokens"][1]["szDecimals"] = json!(9);
    cases.push(value);
    let mut value = metadata_value();
    value["tokens"][1]["weiDecimals"] = json!(78);
    cases.push(value);
    let mut value = metadata_value();
    value["universe"][0]["name"] = json!("BTC");
    cases.push(value);
    let mut value = metadata_value();
    value["universe"][0]["index"] = json!(4_294_967_295_u32);
    value["universe"][0]["name"] = json!("@4294967295");
    cases.push(value);
    for value in cases {
        assert_eq!(decode_metadata(&value).unwrap_err(), HyperCoreError::InvalidMetadata);
    }
}

#[test]
fn rejects_pair_shape_and_integer_substitution_but_allows_extra_fields() {
    for bad_pair in [json!([3]), json!([3,9,3]), json!("3,9"), json!([3,"9"])] {
        let mut value = metadata_value();
        value["universe"][0]["tokens"] = bad_pair;
        assert_eq!(decode_metadata(&value).unwrap_err(), HyperCoreError::MalformedResponse);
    }
    let mut value = metadata_value();
    value["tokens"][0]["fullName"] = Value::Null;
    value["tokens"][0]["evmContract"] = json!({"address":"unconsumed", "evm_extra_wei_decimals":-2});
    value["tokens"][1]["future"] = json!([1,2,3]);
    let market = decode_metadata(&value).unwrap().select_market(
        7, "0x33333333333333333333333333333333", "0x99999999999999999999999999999999"
    ).unwrap();
    assert_eq!(market.action_asset(), 10_007);
}

#[test]
fn exact_response_decimals_preserve_signed_zero_and_reject_lossy_forms() {
    for valid in ["0", "0.0", "-0.000", "-0.00001", "123.4500", "115792089237316195423570985008687907853269984665640564039457584007913129639935"] {
        assert_eq!(ExactDecimal::parse(valid).unwrap().as_str(), valid);
    }
    for invalid in ["", "+1", "1e-8", "NaN", "Infinity", ".1", "1.", " 1", "1 ", "00.1", "--1", "115792089237316195423570985008687907853269984665640564039457584007913129639936"] {
        assert_eq!(ExactDecimal::parse(invalid).unwrap_err(), HyperCoreError::InvalidDecimal);
    }
    assert!(ExactDecimal::parse(&format!("0.{}1", "0".repeat(76))).is_ok());
    assert_eq!(ExactDecimal::parse(&format!("0.{}1", "0".repeat(77))).unwrap_err(), HyperCoreError::InvalidDecimal);
}

#[test]
fn request_constructors_bound_identity_and_time_without_exposing_action_endpoints() {
    for bad in ["0x1", "1111111111111111111111111111111111111111", "0xg111111111111111111111111111111111111111"] {
        assert_eq!(Account::parse(bad).unwrap_err(), HyperCoreError::InvalidAccount);
    }
    assert_eq!(Account::parse("0xAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA").unwrap().to_string(), "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa");
    assert_eq!(Cloid::parse("0xa").unwrap_err(), HyperCoreError::InvalidCloid);
    assert_eq!(TimeRange::new(11,10).unwrap_err(), HyperCoreError::InvalidTimeRange);
    assert!(TimeRange::new(0,u64::MAX).is_ok());
    let cases = [
        (InfoRequest::SpotMeta, json!({"type":"spotMeta"})),
        (InfoRequest::SpotClearinghouseState {user:account()}, json!({"type":"spotClearinghouseState", "user":ACCOUNT})),
        (InfoRequest::UserAbstraction {user:account()}, json!({"type":"userAbstraction", "user":ACCOUNT})),
        (InfoRequest::UserFees {user:account()}, json!({"type":"userFees", "user":ACCOUNT})),
        (InfoRequest::OpenOrders {user:account()}, json!({"type":"openOrders", "user":ACCOUNT, "dex":""})),
        (InfoRequest::OrderStatus {user:account(), oid:OrderId::Oid(u64::MAX)}, json!({"type":"orderStatus", "user":ACCOUNT, "oid":18446744073709551615_u64})),
        (InfoRequest::OrderStatus {user:account(), oid:OrderId::Cloid(Cloid::parse(CLOID).unwrap())}, json!({"type":"orderStatus", "user":ACCOUNT, "oid":CLOID})),
        (fills_request(10,20), json!({"type":"userFillsByTime", "user":ACCOUNT, "startTime":10, "endTime":20, "aggregateByTime":false})),
    ];
    for (request, expected) in cases {
        assert_eq!(serde_json::to_value(request).unwrap(), expected);
    }
}

#[test]
fn fees_are_exact_spot_rates_and_not_an_enforced_fee_policy() {
    let request = InfoRequest::UserFees {user:account()};
    let mut value = json!({"userSpotCrossRate":"0.00049", "userSpotAddRate":"-0.00001", "activeReferralDiscount":"0.0", "feeSchedule":{"spotCross":"0.0007", "spotAdd":"0.0004", "referralDiscount":"0.04", "tiers":{"future":[]}}, "userCrossRate":"unconsumed-perp-rate"});
    let InfoResponse::UserFees(fees) = InfoResponse::decode(&request, &serde_json::to_vec(&value).unwrap()).unwrap() else {panic!("wrong payload")};
    assert_eq!(fees.user_spot_add_rate.as_str(), "-0.00001");
    assert_eq!(fees.fee_schedule.spot_cross.as_str(), "0.0007");
    value["userSpotCrossRate"] = json!(0.00049);
    assert_eq!(InfoResponse::decode(&request, &serde_json::to_vec(&value).unwrap()).unwrap_err(), HyperCoreError::MalformedResponse);
    value["userSpotCrossRate"] = json!("0.00049");
    value["feeSchedule"]["spotAdd"] = json!("1e-4");
    assert_eq!(InfoResponse::decode(&request, &serde_json::to_vec(&value).unwrap()).unwrap_err(), HyperCoreError::MalformedResponse);
}

#[test]
fn mode_and_balances_do_not_invent_exclusive_available_inventory() {
    let request = InfoRequest::UserAbstraction {user:account()};
    let InfoResponse::UserAbstraction(mode) = InfoResponse::decode(&request, br#""futureMode""#).unwrap() else {panic!("wrong payload")};
    assert_eq!(mode.as_str(), "futureMode");
    let request = InfoRequest::SpotClearinghouseState {user:account()};
    let bytes = br#"{"balances":[{"coin":"USDC","token":0,"hold":"0.0","total":"0","entryNtl":"0.0"}],"extra":true}"#;
    let InfoResponse::SpotClearinghouseState(state) = InfoResponse::decode(&request, bytes).unwrap() else {panic!("wrong payload")};
    assert_eq!(state.balances[0].total.as_str(), "0");
    assert_eq!(InfoResponse::decode(&request, br#"{"balances":[{"coin":"USDC","token":0,"hold":"0","total":0,"entryNtl":"0"}]}"#).unwrap_err(), HyperCoreError::MalformedResponse);
}

#[test]
fn preserves_unknown_order_status_and_unknown_oid_without_terminal_inference() {
    let request = InfoRequest::OrderStatus {user:account(), oid:OrderId::Oid(42)};
    let InfoResponse::OrderStatus(status) = InfoResponse::decode(&request, br#"{"status":"unknownOid","future":true}"#).unwrap() else {panic!("wrong payload")};
    assert!(matches!(status, OrderStatus::UnknownOid));
    let mut value = json!({"status":"order", "order":{"order":{"coin":"@7", "side":"B", "limitPx":"12.5", "sz":"0.0", "oid":42, "timestamp":10, "origSz":"1", "tif":"FrontendMarket", "cloid":null, "isTrigger":false, "children":[]}, "status":"futureStatus", "statusTimestamp":20}});
    let InfoResponse::OrderStatus(OrderStatus::Order {status, order, ..}) = InfoResponse::decode(&request, &serde_json::to_vec(&value).unwrap()).unwrap() else {panic!("wrong payload")};
    assert_eq!(status, "futureStatus");
    assert_eq!(order.tif.as_deref(), Some("FrontendMarket"));
    value["order"]["order"]["oid"] = json!(43);
    assert_eq!(InfoResponse::decode(&request, &serde_json::to_vec(&value).unwrap()).unwrap_err(), HyperCoreError::RequestMismatch);
    value["order"]["order"]["oid"] = json!(42);
    value["order"]["status"] = json!(5);
    assert_eq!(InfoResponse::decode(&request, &serde_json::to_vec(&value).unwrap()).unwrap_err(), HyperCoreError::MalformedResponse);
}

#[test]
fn mixed_open_orders_filter_exact_validated_spot_coin_not_ticker() {
    let market = SpotMetadata::decode(META).unwrap().select_market(7,"0x33333333333333333333333333333333","0x99999999999999999999999999999999").unwrap();
    let request = InfoRequest::OpenOrders {user:account()};
    let bytes = br#"[{"coin":"BASE","limitPx":"10","oid":1,"side":"B","sz":"1","timestamp":10},{"coin":"@7","limitPx":"10.0","oid":2,"side":"A","sz":"0.0","timestamp":11},{"coin":"@70","limitPx":"11","oid":3,"side":"B","sz":"1","timestamp":12}]"#;
    let InfoResponse::OpenOrders(orders) = InfoResponse::decode(&request, bytes).unwrap() else {panic!("wrong payload")};
    assert_eq!(orders.scope(), ReadScope::SpotAndFirstDexPerpetuals);
    let selected: Vec<_> = orders.for_market(&market).collect();
    assert_eq!(selected.len(), 1);
    assert_eq!(selected[0].oid, 2);
    assert_eq!(selected[0].side, Side::Sell);
    assert_eq!(InfoResponse::decode(&request, br#"[{"coin":"@7","limitPx":"1","oid":-1,"side":"B","sz":"1","timestamp":1}]"#).unwrap_err(), HyperCoreError::MalformedResponse);
}

#[test]
fn fill_fee_is_inclusive_and_time_history_coverage_is_never_complete() {
    let request = fills_request(10,20);
    let bytes = serde_json::to_vec(&vec![fill(10),fill(20)]).unwrap();
    let InfoResponse::UserFillsByTime(fills) = InfoResponse::decode(&request, &bytes).unwrap() else {panic!("wrong payload")};
    assert_eq!(fills.fills[0].fee.as_str(), "-0.0001");
    assert_eq!(fills.fills[0].builder_fee.as_ref().unwrap().as_str(), "0.00002");
    assert_eq!(fills.fills[0].fee_token, "PURR");
    assert_eq!(fills.scope(), ReadScope::SpotAndPerpetuals);
    assert_eq!(fills.coverage.completeness, CoverageCompleteness::Incomplete);
    assert!(!fills.coverage.saturated);
    for bad_time in [9,21] {
        let bytes = serde_json::to_vec(&vec![fill(bad_time)]).unwrap();
        assert_eq!(InfoResponse::decode(&request, &bytes).unwrap_err(), HyperCoreError::RequestMismatch);
    }
    let bytes = serde_json::to_vec(&vec![fill(20);2_000]).unwrap();
    let InfoResponse::UserFillsByTime(fills) = InfoResponse::decode(&request, &bytes).unwrap() else {panic!("wrong payload")};
    assert!(fills.coverage.saturated);
    assert_eq!(fills.coverage.completeness, CoverageCompleteness::Incomplete);
    let bytes = serde_json::to_vec(&vec![fill(20);2_001]).unwrap();
    assert_eq!(InfoResponse::decode(&request, &bytes).unwrap_err(), HyperCoreError::MalformedResponse);
    let InfoResponse::UserFillsByTime(empty) = InfoResponse::decode(&request, b"[]").unwrap() else {panic!("wrong payload")};
    assert_eq!(empty.coverage.completeness, CoverageCompleteness::Incomplete);
}

#[test]
fn malformed_and_oversized_info_bodies_are_redacted_typed_errors() {
    let bytes = vec![b' '; MAX_INFO_RESPONSE_BYTES+1];
    assert_eq!(InfoResponse::decode(&InfoRequest::SpotMeta,&bytes).unwrap_err(), HyperCoreError::ResponseTooLarge);
    let error = InfoResponse::decode(&InfoRequest::SpotMeta, b"private unexpected response").unwrap_err();
    assert_eq!(error, HyperCoreError::MalformedResponse);
    assert!(!error.to_string().contains("private"));
    assert_eq!(InfoResponse::decode(&InfoRequest::SpotMeta, b"null").unwrap_err(), HyperCoreError::MalformedResponse);
}

#[test]
fn selected_pair_action_asset_checks_exact_u32_boundary() {
    let mut value = metadata_value();
    value["universe"][0]["index"] = json!(4_294_957_295_u32);
    value["universe"][0]["name"] = json!("@4294957295");
    let market = decode_metadata(&value).unwrap().select_market(
        4_294_957_295, "0x33333333333333333333333333333333", "0x99999999999999999999999999999999"
    ).unwrap();
    assert_eq!(market.action_asset(), u32::MAX);
    value["universe"][0]["index"] = json!(4_294_957_296_u32);
    value["universe"][0]["name"] = json!("@4294957296");
    assert_eq!(decode_metadata(&value).unwrap_err(), HyperCoreError::InvalidMetadata);
}

#[test]
fn response_id_and_timestamp_fields_must_be_u64_integers() {
    let request = InfoRequest::OpenOrders {user:account()};
    let mut order = json!({"coin":"@7", "limitPx":"1", "oid":18446744073709551615_u64, "side":"B", "sz":"1", "timestamp":18446744073709551615_u64});
    let bytes = serde_json::to_vec(&vec![order.clone()]).unwrap();
    let InfoResponse::OpenOrders(orders) = InfoResponse::decode(&request, &bytes).unwrap() else {panic!("wrong payload")};
    assert_eq!(orders.orders[0].oid, u64::MAX);
    for (field, invalid) in [("oid",json!(1.0)), ("timestamp",json!("1")), ("timestamp",json!(-1)), ("side",json!("buy")), ("sz",json!(1))] {
        let original = order[field].clone();
        order[field] = invalid;
        assert_eq!(InfoResponse::decode(&request, &serde_json::to_vec(&vec![order.clone()]).unwrap()).unwrap_err(), HyperCoreError::MalformedResponse);
        order[field] = original;
    }
    let oversized = br#"[{"coin":"@7","limitPx":"1","oid":18446744073709551616,"side":"B","sz":"1","timestamp":0}]"#;
    assert_eq!(InfoResponse::decode(&request, oversized).unwrap_err(), HyperCoreError::MalformedResponse);
}

#[test]
fn order_status_cloid_response_must_match_the_requested_identity() {
    let request = InfoRequest::OrderStatus {user:account(), oid:OrderId::Cloid(Cloid::parse(CLOID).unwrap())};
    let mut value = json!({"status":"order", "order":{"order":{"coin":"@7", "side":"B", "limitPx":"12.5", "sz":"0", "oid":42, "timestamp":10, "origSz":"1", "tif":null, "cloid":CLOID}, "status":"filled", "statusTimestamp":20}});
    let response = InfoResponse::decode(&request, &serde_json::to_vec(&value).unwrap()).unwrap();
    assert!(matches!(response, InfoResponse::OrderStatus(OrderStatus::Order {status, ..}) if status == "filled"));
    value["order"]["order"]["cloid"] = json!("0x0000000000000000000000000000000b");
    assert_eq!(InfoResponse::decode(&request, &serde_json::to_vec(&value).unwrap()).unwrap_err(), HyperCoreError::RequestMismatch);
    value["order"]["order"]["cloid"] = Value::Null;
    assert_eq!(InfoResponse::decode(&request, &serde_json::to_vec(&value).unwrap()).unwrap_err(), HyperCoreError::RequestMismatch);
    value["order"]["order"]["cloid"] = json!("0x0a");
    assert_eq!(InfoResponse::decode(&request, &serde_json::to_vec(&value).unwrap()).unwrap_err(), HyperCoreError::MalformedResponse);
}

#[test]
fn malformed_consumed_fill_fee_and_identity_are_rejected_without_double_counting() {
    let request = fills_request(10,20);
    for (field, invalid) in [("fee",json!(0.1)), ("builderFee",json!("NaN")), ("feeToken",json!("")), ("hash",json!("0x01")), ("tid",json!(-1)), ("px",json!("1e2"))] {
        let mut value = fill(15);
        value[field] = invalid;
        assert_eq!(InfoResponse::decode(&request, &serde_json::to_vec(&vec![value]).unwrap()).unwrap_err(), HyperCoreError::MalformedResponse);
    }
}

#[test]
fn historical_order_zero_size_is_allowed_but_negative_magnitude_is_not() {
    let request = InfoRequest::OpenOrders {user:account()};
    let mut value = json!({"coin":"@7", "limitPx":"0", "oid":1, "side":"B", "sz":"0.0", "timestamp":0});
    assert!(InfoResponse::decode(&request, &serde_json::to_vec(&vec![value.clone()]).unwrap()).is_ok());
    for field in ["sz", "limitPx"] {
        value[field] = json!("-0.1");
        assert_eq!(InfoResponse::decode(&request, &serde_json::to_vec(&vec![value.clone()]).unwrap()).unwrap_err(), HyperCoreError::MalformedResponse);
        value[field] = json!("0");
    }
    let request = fills_request(10,20);
    for field in ["sz", "px"] {
        let mut value = fill(15);
        value[field] = json!("-1");
        assert_eq!(InfoResponse::decode(&request, &serde_json::to_vec(&vec![value]).unwrap()).unwrap_err(), HyperCoreError::MalformedResponse);
    }
}

#[test]
fn short_empty_or_unknown_status_envelopes_never_become_terminal_states() {
    let request = InfoRequest::OrderStatus {user:account(), oid:OrderId::Oid(1)};
    for bytes in [
        br#"{"status":"unknownFutureEnvelope"}"#.as_slice(),
        br#"{"status":"order","order":{"status":"filled","statusTimestamp":1}}"#.as_slice(),
        br#"{"status":"order","order":{"order":{"coin":"@7","side":"B","limitPx":"1","sz":"0","oid":1,"timestamp":1,"origSz":"1"},"status":"","statusTimestamp":1}}"#.as_slice(),
    ] {
        assert_eq!(InfoResponse::decode(&request, bytes).unwrap_err(), HyperCoreError::MalformedResponse);
    }
}

#[test]
fn numeric_aliases_and_case_different_duplicate_token_ids_do_not_select_assets() {
    let mut value = metadata_value();
    value["tokens"][0]["tokenId"] = json!("0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa");
    value["tokens"][1]["tokenId"] = json!("0xAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA");
    assert_eq!(decode_metadata(&value).unwrap_err(), HyperCoreError::InvalidMetadata);
    for alias in ["@07", "@8", "PURR/USDC"] {
        let mut value = metadata_value();
        value["universe"][0]["name"] = json!(alias);
        assert_eq!(decode_metadata(&value).unwrap_err(), HyperCoreError::InvalidMetadata);
    }
    for index in [json!(-1), json!(4_294_967_296_u64), json!(7.0), json!("7")] {
        let mut value = metadata_value();
        value["universe"][0]["index"] = index;
        assert_eq!(decode_metadata(&value).unwrap_err(), HyperCoreError::MalformedResponse);
    }
}

#[test]
fn bounded_decoder_accepts_the_byte_limit_without_inventing_a_selected_market() {
    let mut bytes = META.to_vec();
    bytes.resize(MAX_INFO_RESPONSE_BYTES, b' ');
    let InfoResponse::SpotMeta(metadata) = InfoResponse::decode(&InfoRequest::SpotMeta, &bytes).unwrap() else {panic!("wrong payload")};
    assert_eq!(metadata.select_market(8,"0x33333333333333333333333333333333","0x99999999999999999999999999999999").unwrap_err(), HyperCoreError::AssetMismatch);
    bytes.push(b' ');
    assert_eq!(InfoResponse::decode(&InfoRequest::SpotMeta, &bytes).unwrap_err(), HyperCoreError::ResponseTooLarge);
}
