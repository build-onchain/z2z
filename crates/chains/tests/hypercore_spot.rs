use serde_json::{Value, json};
use ziquid_chains::hypercore::{Account, Cloid, Network, OrderId, Side, SpotMarket, SpotMetadata};
use ziquid_chains::hypercore::spot::{
    FeeCap, SpotCancelIntent, SpotOrderIntent, SpotPreparationError, SpotTif,
    prepare_spot_cancel, prepare_spot_order,
};

#[test]
fn prepares_exact_selected_spot_action_without_claiming_hard_fee_enforcement() {
    let meta = SpotMetadata::decode(include_bytes!("fixtures/hypercore-testnet-spot-meta.json")).unwrap();
    let market = meta.select_market(0, "0xc4bf3f870c0e9465323c0b6ed28096c2", "0xeb62eee3685fc4c43992febcd9e75443").unwrap();
    let intent = SpotOrderIntent {
        network: Network::Testnet,
        account: Account::parse("0x1111111111111111111111111111111111111111").unwrap(),
        nonce: 1_700_000_000_000, expires_after_ms: 1_700_000_060_000,
        cloid: Cloid::parse("0x00000000000000000000000000000001").unwrap(),
        side: Side::Buy, size: "2.000".into(), limit_price: "10.00".into(), tif: SpotTif::Gtc,
        fee_cap: FeeCap { token_id: "0xeb62eee3685fc4c43992febcd9e75443".into(), max_atoms: "100".into() },
    };
    let prepared = prepare_spot_order(&market, &intent).unwrap();
    assert_eq!(prepared.action_json(), r#"{"type":"order","orders":[{"a":10000,"b":true,"p":"10","s":"2","r":false,"t":{"limit":{"tif":"Gtc"}},"c":"0x00000000000000000000000000000001"}],"grouping":"na"}"#);
    let output = serde_json::to_value(&prepared).unwrap();
    assert_eq!(output["fee_cap_enforcement"], "NotVenueEnforced");
    assert_eq!(output["signing_ready"], false);
    assert_eq!(output["submission_ready"], false);
}

const BASE: &str = "0x33333333333333333333333333333333";
const QUOTE: &str = "0x99999999999999999999999999999999";
const U256_MAX: &str = "115792089237316195423570985008687907853269984665640564039457584007913129639935";
const U256_OVERFLOW: &str = "115792089237316195423570985008687907853269984665640564039457584007913129639936";

fn metadata(size_decimals: u8) -> Value {
    json!({
        "tokens": [
            {"name":"QUOTE", "szDecimals":8, "weiDecimals":0, "index":9,
             "tokenId":QUOTE, "isCanonical":true},
            {"name":"BASE", "szDecimals":size_decimals, "weiDecimals":8, "index":3,
             "tokenId":BASE, "isCanonical":true}
        ],
        "universe":[{"name":"@7", "tokens":[3,9], "index":7, "isCanonical":true}]
    })
}

fn select(value: &Value) -> SpotMarket {
    SpotMetadata::decode(&serde_json::to_vec(value).unwrap()).unwrap()
        .select_market(7, BASE, QUOTE).unwrap()
}

fn order() -> SpotOrderIntent {
    SpotOrderIntent {
        network: Network::Testnet,
        account: Account::parse("0x1111111111111111111111111111111111111111").unwrap(),
        nonce: 100,
        expires_after_ms: 200,
        cloid: Cloid::parse("0x00000000000000000000000000000001").unwrap(),
        side: Side::Buy,
        size: "2".into(),
        limit_price: "10".into(),
        tif: SpotTif::Gtc,
        fee_cap: FeeCap { token_id: QUOTE.into(), max_atoms: "100".into() },
    }
}

fn cancel(order: OrderId) -> SpotCancelIntent {
    let terms = self::order();
    SpotCancelIntent {
        network: terms.network,
        account: terms.account,
        nonce: terms.nonce,
        expires_after_ms: terms.expires_after_ms,
        order,
    }
}

#[test]
fn sparse_asset_and_sell_tif_are_encoded_in_fixed_wire_order() {
    let market = select(&metadata(2));
    let mut terms = order();
    terms.side = Side::Sell;
    terms.size = "2.34000".into();
    terms.limit_price = "0.123400".into();
    terms.tif = SpotTif::Alo;
    let prepared = prepare_spot_order(&market, &terms).unwrap();
    assert_eq!(prepared.action_json(), r#"{"type":"order","orders":[{"a":10007,"b":false,"p":"0.1234","s":"2.34","r":false,"t":{"limit":{"tif":"Alo"}},"c":"0x00000000000000000000000000000001"}],"grouping":"na"}"#);
    terms.tif = SpotTif::Ioc;
    assert_eq!(serde_json::from_str::<Value>(prepare_spot_order(&market, &terms).unwrap().action_json()).unwrap()["orders"][0]["t"]["limit"]["tif"], "Ioc");
}

#[test]
fn price_tick_and_significant_digits_do_not_use_quote_atom_precision() {
    for size_decimals in [0, 1] {
        let mut terms = order();
        terms.limit_price = "0.000123400000".into();
        assert!(prepare_spot_order(&select(&metadata(size_decimals)), &terms).is_ok());
    }
    let market = select(&metadata(2));
    let mut terms = order();
    for price in ["0.0001234", "12345.6", "1.000001"] {
        terms.limit_price = price.into();
        assert_eq!(prepare_spot_order(&market, &terms).unwrap_err(), SpotPreparationError::InvalidPrecision);
    }
    for price in ["123456", "123456.000", "123.45", "0.000001", U256_MAX] {
        terms.limit_price = price.into();
        assert!(prepare_spot_order(&market, &terms).is_ok(), "{price}");
    }
    let market = select(&metadata(8));
    terms.limit_price = "1.1".into();
    assert_eq!(prepare_spot_order(&market, &terms).unwrap_err(), SpotPreparationError::InvalidPrecision);
    terms.limit_price = "123456".into();
    assert!(prepare_spot_order(&market, &terms).is_ok());
}

#[test]
fn size_precision_and_redundant_zeroes_preserve_exact_lots() {
    let market = select(&metadata(2));
    let mut terms = order();
    terms.size = "0.010000".into();
    assert_eq!(serde_json::from_str::<Value>(prepare_spot_order(&market, &terms).unwrap().action_json()).unwrap()["orders"][0]["s"], "0.01");
    terms.size = "0.001".into();
    assert_eq!(prepare_spot_order(&market, &terms).unwrap_err(), SpotPreparationError::InvalidPrecision);
    terms.size = format!("2.{}", "0".repeat(500));
    let normalized = prepare_spot_order(&market, &terms).unwrap();
    assert_eq!(normalized.intent_digest(), prepare_spot_order(&market, &order()).unwrap().intent_digest());
    terms.size = format!("2.{}", "0".repeat(511));
    assert_eq!(prepare_spot_order(&market, &terms).unwrap_err(), SpotPreparationError::InputBounds);
}

#[test]
fn rejects_nonpositive_noncanonical_and_overflow_decimals_without_echoing_them() {
    let market = select(&metadata(2));
    for invalid in ["", "0", "0.000", "-1", "+1", "1e2", "NaN", "Infinity", ".1", "1.", "01", "00.1", " 1", "1 ", "1.2.0", "１", U256_OVERFLOW] {
        for size in [true, false] {
            let mut terms = order();
            if size { terms.size = invalid.into(); } else { terms.limit_price = invalid.into(); }
            let error = prepare_spot_order(&market, &terms).unwrap_err();
            assert_eq!(error, SpotPreparationError::InvalidNumber, "{invalid}");
            assert_eq!(error.to_string(), "invalid spot number");
        }
    }
    let mut terms = order();
    terms.size = U256_MAX.into();
    assert!(prepare_spot_order(&market, &terms).is_ok());
}

#[test]
fn requested_caps_bind_exact_selected_token_and_canonical_u256_atoms() {
    let market = select(&metadata(2));
    let mut terms = order();
    for token in [BASE, QUOTE] {
        terms.fee_cap.token_id = token.to_ascii_uppercase();
        for atoms in ["0", "100", U256_MAX] {
            terms.fee_cap.max_atoms = atoms.into();
            let output = serde_json::to_value(prepare_spot_order(&market, &terms).unwrap()).unwrap();
            assert_eq!(output["fee_cap"], json!({"token_id":token, "max_atoms":atoms}));
            assert_eq!(output["fee_cap_enforcement"], "NotVenueEnforced");
        }
    }
    for token in ["USDC", "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", "0x99", ""] {
        terms.fee_cap.token_id = token.into();
        assert_eq!(prepare_spot_order(&market, &terms).unwrap_err(), SpotPreparationError::InvalidFeeCap);
    }
    terms.fee_cap.token_id = QUOTE.into();
    for atoms in ["", "00", "01", "-1", "+1", "1.0", "1e2", " 1", U256_OVERFLOW] {
        terms.fee_cap.max_atoms = atoms.into();
        assert_eq!(prepare_spot_order(&market, &terms).unwrap_err(), SpotPreparationError::InvalidFeeCap);
    }
    assert!(serde_json::from_value::<FeeCap>(json!({"token_id":QUOTE, "max_atoms":"1", "rate":"0.1"})).is_err());
}

#[test]
fn local_digest_binds_every_immutable_choice_and_full_metadata_source() {
    let market = select(&metadata(2));
    let original = order();
    let prepared = prepare_spot_order(&market, &original).unwrap();
    let baseline = prepared.intent_digest();
    let mut variants = Vec::new();
    let mut terms = original.clone();
    terms.account = Account::parse("0x2222222222222222222222222222222222222222").unwrap();
    variants.push(terms);
    let mut terms = original.clone(); terms.nonce += 1; variants.push(terms);
    let mut terms = original.clone(); terms.expires_after_ms += 1; variants.push(terms);
    let mut terms = original.clone(); terms.fee_cap.max_atoms = "101".into(); variants.push(terms);
    let mut terms = original.clone(); terms.fee_cap.token_id = BASE.into(); variants.push(terms);
    let mut terms = original.clone(); terms.cloid = Cloid::parse("0x00000000000000000000000000000002").unwrap(); variants.push(terms);
    let mut terms = original.clone(); terms.side = Side::Sell; variants.push(terms);
    let mut terms = original.clone(); terms.size = "3".into(); variants.push(terms);
    let mut terms = original.clone(); terms.limit_price = "11".into(); variants.push(terms);
    let mut terms = original.clone(); terms.tif = SpotTif::Ioc; variants.push(terms);
    for variant in variants {
        assert_ne!(baseline, prepare_spot_order(&market, &variant).unwrap().intent_digest());
    }
    let mut changed_source = metadata(2);
    changed_source["future"] = json!(true);
    assert_ne!(baseline, prepare_spot_order(&select(&changed_source), &original).unwrap().intent_digest());
    changed_source = metadata(2);
    changed_source["tokens"][1]["fullName"] = json!("Different selected token label");
    assert_ne!(baseline, prepare_spot_order(&select(&changed_source), &original).unwrap().intent_digest());
    let mut terms = original.clone();
    terms.size = "2.0000".into(); terms.limit_price = "10.0000".into();
    terms.fee_cap.token_id = QUOTE.to_ascii_uppercase();
    assert_eq!(baseline, prepare_spot_order(&market, &terms).unwrap().intent_digest());
    assert_eq!(baseline, prepare_spot_order(&market, &original).unwrap().intent_digest());
    assert_ne!(baseline, prepare_spot_cancel(&market, &cancel(OrderId::Cloid(original.cloid))).unwrap().intent_digest());
}

#[test]
fn nonce_expiry_and_nonzero_order_identifiers_are_required_for_both_actions() {
    let market = select(&metadata(2));
    for (nonce, expiry) in [(0, 1), (1, 1), (2, 1)] {
        let mut terms = order(); terms.nonce = nonce; terms.expires_after_ms = expiry;
        assert_eq!(prepare_spot_order(&market, &terms).unwrap_err(), SpotPreparationError::InvalidNonce);
        let mut terms = cancel(OrderId::Oid(1)); terms.nonce = nonce; terms.expires_after_ms = expiry;
        assert_eq!(prepare_spot_cancel(&market, &terms).unwrap_err(), SpotPreparationError::InvalidNonce);
    }
    let zero = Cloid::parse("0x00000000000000000000000000000000").unwrap();
    let mut terms = order(); terms.cloid = zero;
    assert_eq!(prepare_spot_order(&market, &terms).unwrap_err(), SpotPreparationError::InvalidOrder);
    for identifier in [OrderId::Oid(0), OrderId::Cloid(zero)] {
        assert_eq!(prepare_spot_cancel(&market, &cancel(identifier)).unwrap_err(), SpotPreparationError::InvalidOrder);
    }
}

#[test]
fn oid_and_cloid_cancels_are_distinct_exact_actions_not_confirmed_outcomes() {
    let market = select(&metadata(2));
    let oid = prepare_spot_cancel(&market, &cancel(OrderId::Oid(u64::MAX))).unwrap();
    assert_eq!(oid.action_json(), r#"{"type":"cancel","cancels":[{"a":10007,"o":18446744073709551615}]}"#);
    let cloid = prepare_spot_cancel(&market, &cancel(OrderId::Cloid(order().cloid))).unwrap();
    assert_eq!(cloid.action_json(), r#"{"type":"cancelByCloid","cancels":[{"asset":10007,"cloid":"0x00000000000000000000000000000001"}]}"#);
    assert_ne!(oid.intent_digest(), cloid.intent_digest());
    for prepared in [oid, cloid, prepare_spot_order(&market, &order()).unwrap()] {
        let output = serde_json::to_value(prepared).unwrap();
        assert_eq!(output["schema_version"], 1);
        assert_eq!(output["network"], "testnet");
        assert_eq!(output["signer"], output["account"]);
        assert_eq!(output["market"], serde_json::to_value(&market).unwrap());
        assert_eq!(output["outcome"], "PreparedProposal");
        assert_eq!(output["fee_cap_enforcement"], "NotVenueEnforced");
        for flag in ["signing_material_generated", "signing_ready", "submission_ready", "durable_reservation"] {
            assert_eq!(output[flag], false);
        }
        for qualification in ["source_validity", "account_mode", "nonce_validity"] {
            assert_eq!(output[qualification], "UNVERIFIED");
        }
    }
    let output = serde_json::to_value(prepare_spot_cancel(&market, &cancel(OrderId::Oid(1))).unwrap()).unwrap();
    assert!(output.get("fee_cap").is_none());
}

#[test]
fn local_digest_uses_domain_schema_and_exact_ordered_substantive_record() {
    use sha2::{Digest, Sha256};
    let value = metadata(2);
    let source = serde_json::to_vec(&value).unwrap();
    let source_digest: [u8; 32] = Sha256::digest(&source).into();
    let expected_market = format!(
        r#"{{"pair":{{"name":"@7","tokens":[3,9],"index":7,"isCanonical":true,"actionAsset":10007}},"base":{{"name":"BASE","index":3,"tokenId":"{BASE}","szDecimals":2,"weiDecimals":8,"isCanonical":true,"fullName":null}},"quote":{{"name":"QUOTE","index":9,"tokenId":"{QUOTE}","szDecimals":8,"weiDecimals":0,"isCanonical":true,"fullName":null}},"metadata_sha256":{}}}"#,
        serde_json::to_string(&source_digest).unwrap(),
    );
    let expected_action = r#"{"type":"order","orders":[{"a":10007,"b":true,"p":"10","s":"2","r":false,"t":{"limit":{"tif":"Gtc"}},"c":"0x00000000000000000000000000000001"}],"grouping":"na"}"#;
    let expected_record = format!(
        r#"{{"kind":"order","network":"testnet","account":"0x1111111111111111111111111111111111111111","signer":"0x1111111111111111111111111111111111111111","nonce":100,"expires_after_ms":200,"market":{expected_market},"fee_cap":{{"token_id":"{QUOTE}","max_atoms":"100"}},"action_json":{}}}"#,
        serde_json::to_string(expected_action).unwrap(),
    );
    let mut expected_digest = Sha256::new();
    expected_digest.update(b"Z2Z_HYPERCORE_SPOT_PROPOSAL\0");
    expected_digest.update([0, 1]);
    expected_digest.update(expected_record.as_bytes());
    let expected_digest: [u8; 32] = expected_digest.finalize().into();
    let prepared = prepare_spot_order(&select(&value), &order()).unwrap();
    assert_eq!(prepared.intent_digest(), expected_digest);
}

#[test]
fn cancel_digest_binds_scope_window_source_and_exact_identifier() {
    let market = select(&metadata(2));
    let original = cancel(OrderId::Oid(1));
    let baseline = prepare_spot_cancel(&market, &original).unwrap().intent_digest();
    let mut variants = Vec::new();
    let mut terms = original.clone(); terms.nonce += 1; variants.push(terms);
    let mut terms = original.clone(); terms.expires_after_ms += 1; variants.push(terms);
    let mut terms = original.clone(); terms.order = OrderId::Oid(2); variants.push(terms);
    let mut terms = original.clone();
    terms.account = Account::parse("0x2222222222222222222222222222222222222222").unwrap();
    variants.push(terms);
    for variant in variants {
        assert_ne!(baseline, prepare_spot_cancel(&market, &variant).unwrap().intent_digest());
    }
    let mut source = metadata(2); source["future"] = json!(true);
    assert_ne!(baseline, prepare_spot_cancel(&select(&source), &original).unwrap().intent_digest());
}

#[test]
fn bounds_apply_to_each_owned_text_before_unbounded_work() {
    let market = select(&metadata(2));
    for field in ["size", "price", "fee_token", "fee_atoms"] {
        let mut terms = order();
        let oversize = "1".repeat(513);
        match field {
            "size" => terms.size = oversize,
            "price" => terms.limit_price = oversize,
            "fee_token" => terms.fee_cap.token_id = oversize,
            "fee_atoms" => terms.fee_cap.max_atoms = oversize,
            _ => unreachable!(),
        }
        assert_eq!(prepare_spot_order(&market, &terms).unwrap_err(), SpotPreparationError::InputBounds);
    }
}
