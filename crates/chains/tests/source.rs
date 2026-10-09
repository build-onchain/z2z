//! Controlled raw source acquisition, not canonicality, finality or financial proof.

use std::time::Duration;
use ziquid_chains::source::{RawBlockClient, RawBlockError};

#[test]
fn raw_source_client_rejects_nonliteral_http_before_acquisition() {
    let error = RawBlockClient::new(
        "http://127.1/rpc?private-source-sentinel", true,
        100_000, Duration::from_secs(5),
    ).unwrap_err();
    assert_eq!(error, RawBlockError::InvalidEndpoint);
    assert!(!format!("{error:?}: {error}").contains("private-source-sentinel"));
}

#[path = "support/source.rs"]
mod support;
use support::{BODIES, Fixture, SENTINEL, Step, Wire, display_hash, hash, hex, reply};
use serde_json::json;

fn client(fixture: &Fixture) -> RawBlockClient {
    RawBlockClient::new(fixture.endpoint(), true, 1_000_000, Duration::from_secs(5)).unwrap()
}

fn hash_step(wire: Wire) -> Step {
    let mut step = Step::hash(1, 0);
    step.wire = wire;
    step
}

async fn rejected_hash(response: Vec<u8>, expected: RawBlockError) {
    let fixture = Fixture::start(vec![hash_step(Wire::Json(response))]);
    let mut body = vec![0x55];
    let error = client(&fixture).read_block(0, &mut body, 2_000_000).await.unwrap_err();
    assert_eq!(error, expected);
    assert_eq!(fixture.calls(), 1);
    assert!(!format!("{error:?}: {error}").contains(SENTINEL));
}

#[tokio::test]
async fn authentic_zero_through_ten_uses_exact_contiguous_requests_and_final_recheck() {
    let mut steps = Vec::new();
    for height in 0..=10 {
        let id = 2 * u64::from(height) + 1;
        steps.push(Step::hash(id, height));
        let mut step = Step::body(id + 1, height as usize);
        // Real fragmented HTTP transfer; the raw block itself is unmodified.
        step.wire = Wire::Chunked(reply(id + 1, json!(hex(BODIES[height as usize]))), 17);
        steps.push(step);
    }
    let mut final_step = Step::hash(23, 10);
    final_step.wire = Wire::Json(reply(23, json!(display_hash(10).to_ascii_uppercase())));
    steps.push(final_step);
    let fixture = Fixture::start(steps);
    let mut client = client(&fixture);
    assert!(!format!("{client:?}").contains(SENTINEL));
    let mut body = Vec::new();
    for height in 0..=10 {
        let acquired = client.read_block(height, &mut body, 2_000_000).await.unwrap();
        assert_eq!(body, BODIES[height as usize]);
        assert_eq!(acquired, hash(height as usize));
        if height == 0 {
            assert_eq!(hex(&acquired), "382c4a332661c7ed0671f32a34d724619f086c61873bce7c99859dd9920aa605");
        }
    }
    client.recheck_hash(10, hash(10)).await.unwrap();
    assert_eq!(fixture.calls(), 23);
}

#[tokio::test]
async fn source_success_accepts_absent_error_and_escaped_result_strings() {
    let mut first = Step::hash(1, 0);
    first.wire = Wire::Json(format!("{{\"jsonrpc\":\"2.0\",\"id\":1,\"result\":\"{}\"}}", display_hash(0)).into_bytes());
    let mut second = Step::body(2, 0);
    let raw = hex(BODIES[0]);
    second.wire = Wire::Json(format!("{{\"jsonrpc\":\"2.0\",\"id\":2,\"result\":\"\\u0030{}\",\"error\":null}}", &raw[1..]).into_bytes());
    let fixture = Fixture::start(vec![first, second]);
    let mut body = Vec::new();
    assert_eq!(client(&fixture).read_block(0, &mut body, 1692).await.unwrap(), hash(0));
    assert_eq!(body, BODIES[0]);
}

#[tokio::test]
async fn matching_numeric_id_and_exact_jsonrpc_version_are_required() {
    let valid = reply(1, json!(display_hash(0)));
    let text = std::str::from_utf8(&valid).unwrap();
    for (from, to) in [
        ("\"id\":1", "\"id\":2"),
        ("\"id\":1", "\"id\":\"1\""),
        ("\"id\":1", "\"id\":1.0"),
        ("\"id\":1", "\"id\":null"),
        ("\"id\":1,", ""),
        ("\"jsonrpc\":\"2.0\"", "\"jsonrpc\":\"1.0\""),
        ("\"jsonrpc\":\"2.0\"", "\"jsonrpc\":2"),
        ("\"jsonrpc\":\"2.0\",", ""),
    ] {
        rejected_hash(text.replace(from, to).into_bytes(), RawBlockError::MalformedResponse).await;
    }
}

#[tokio::test]
async fn duplicate_fields_and_nonobject_or_trailing_envelopes_are_rejected() {
    let base = format!("{{\"jsonrpc\":\"2.0\",\"id\":1,\"result\":\"{}\",\"error\":null}}", display_hash(0));
    for extra in ["\"id\":1", "\"jsonrpc\":\"2.0\"", "\"result\":null", "\"error\":null", "\"private\":1"] {
        let envelope = format!("{},{} }}", &base[..base.len() - 1], extra);
        rejected_hash(envelope.into_bytes(), RawBlockError::MalformedResponse).await;
    }
    for envelope in [format!("[{base}]"), format!("{base} {{}}"), format!("{base} trailing"),
        format!("[\"2.0\",1,\"{}\",null]", display_hash(0))] {
        rejected_hash(envelope.into_bytes(), RawBlockError::MalformedResponse).await;
    }
}

#[tokio::test]
async fn typed_rpc_rejection_retains_only_code_and_conflicting_null_profiles_fail() {
    rejected_hash(json!({"jsonrpc":"2.0", "id":1, "result":null,
        "error":{"code":-8, "message":SENTINEL, "data":{"private":SENTINEL}}})
        .to_string().into_bytes(), RawBlockError::RpcRejected(-8)).await;
    for fields in [
        json!({"result":display_hash(0), "error":{"code":-8,"message":SENTINEL}}),
        json!({"result":null, "error":null}),
        json!({"result":true}),
        json!({}),
        json!({"error":[-8,SENTINEL]}),
        json!({"error":{"code":"-8","message":SENTINEL}}),
        json!({"error":{"code":-8,"message":42}}),
        json!({"error":{"code":-8}}),
    ] {
        let mut envelope = fields;
        envelope["jsonrpc"] = json!("2.0");
        envelope["id"] = json!(1);
        rejected_hash(envelope.to_string().into_bytes(), RawBlockError::MalformedResponse).await;
    }
    for error in [
        "{\"code\":-8,\"code\":-9,\"message\":\"private\"}",
        "{\"code\":-8,\"message\":\"private\",\"message\":\"again\"}",
        "{\"code\":-8,\"message\":\"private\",\"data\":null,\"data\":null}",
    ] {
        rejected_hash(format!("{{\"jsonrpc\":\"2.0\",\"id\":1,\"error\":{error}}}").into_bytes(),
            RawBlockError::MalformedResponse).await;
    }
}

#[tokio::test]
async fn claimed_hash_requires_exact_unprefixed_ascii_hex_width() {
    for result in ["".to_owned(), "00".to_owned(), "0x".to_owned() + &display_hash(0),
        "g".repeat(64), "0".repeat(65), "é".repeat(32)] {
        rejected_hash(reply(1, json!(result)), RawBlockError::MalformedResponse).await;
    }
}

async fn rejected_body(result: String, limit: usize, expected: RawBlockError) {
    let mut second = Step::body(2, 0);
    second.wire = Wire::Json(reply(2, json!(result)));
    let fixture = Fixture::start(vec![Step::hash(1, 0), second]);
    let mut body = Vec::new();
    let error = client(&fixture).read_block(0, &mut body, limit).await.unwrap_err();
    assert_eq!(error, expected);
    assert_eq!(fixture.calls(), 2);
    assert!(body.len() <= limit);
}

#[tokio::test]
async fn raw_body_rejects_empty_odd_prefixed_and_invalid_digits() {
    for result in ["", "0", "0x00", "gg", "é"] {
        rejected_body(result.to_owned(), 1692, RawBlockError::MalformedResponse).await;
    }
}

#[tokio::test]
async fn decoded_body_ceiling_is_applied_before_resize() {
    rejected_body(hex(BODIES[0]), 1691, RawBlockError::BodyTooLarge).await;
    let mut second = Step::body(2, 0);
    second.wire = Wire::Json(reply(2, json!("00".repeat(2_000_001))));
    let fixture = Fixture::start(vec![Step::hash(1, 0), second]);
    let mut client = RawBlockClient::new(fixture.endpoint(), true, 5_000_000, Duration::from_secs(5)).unwrap();
    let mut body = Vec::new();
    assert_eq!(client.read_block(0, &mut body, usize::MAX).await.unwrap_err(), RawBlockError::BodyTooLarge);
    assert_eq!(body.capacity(), 0);
}

#[tokio::test]
async fn hash_response_ceiling_covers_advertised_and_actual_chunked_bytes() {
    for wire in [Wire::Advertised(4097), Wire::Chunked(vec![b' '; 4097], 31)] {
        let fixture = Fixture::start(vec![hash_step(wire)]);
        assert_eq!(client(&fixture).read_block(0, &mut Vec::new(), 1692).await.unwrap_err(),
            RawBlockError::ResponseTooLarge);
        assert_eq!(fixture.calls(), 1);
    }
}

#[tokio::test]
async fn body_response_ceiling_covers_advertised_and_actual_chunked_bytes() {
    for wire in [Wire::Advertised(4_004_097), Wire::Chunked(vec![b' '; 4_004_097], 4096)] {
        let mut step = Step::body(2, 0);
        step.wire = wire;
        let fixture = Fixture::start(vec![Step::hash(1, 0), step]);
        let mut client = RawBlockClient::new(fixture.endpoint(), true, 5_000_000, Duration::from_secs(5)).unwrap();
        assert_eq!(client.read_block(0, &mut Vec::new(), 2_000_000).await.unwrap_err(),
            RawBlockError::ResponseTooLarge);
    }
}

#[tokio::test]
async fn cumulative_rpc_budget_counts_hash_body_and_final_recheck() {
    let hash_bytes = reply(1, json!(display_hash(0))).len() as u64;
    let body_bytes = reply(2, json!(hex(BODIES[0]))).len() as u64;
    let recheck_bytes = reply(3, json!(display_hash(0))).len() as u64;
    let exact = hash_bytes + body_bytes + recheck_bytes;
    for budget in [exact, exact - 1] {
        let fixture = Fixture::start(vec![Step::hash(1, 0), Step::body(2, 0), Step::hash(3, 0)]);
        let mut client = RawBlockClient::new(fixture.endpoint(), true, budget, Duration::from_secs(5)).unwrap();
        let acquired = client.read_block(0, &mut Vec::new(), 1692).await.unwrap();
        let result = client.recheck_hash(0, acquired).await;
        assert_eq!(result, if budget == exact { Ok(()) } else { Err(RawBlockError::RpcBudgetExceeded) });
        assert_eq!(fixture.calls(), 3);
    }
    let fixture = Fixture::start(vec![hash_step(Wire::Chunked(reply(1, json!(display_hash(0))), 7))]);
    let mut client = RawBlockClient::new(fixture.endpoint(), true, hash_bytes - 1, Duration::from_secs(5)).unwrap();
    assert_eq!(client.read_block(0, &mut Vec::new(), 1692).await.unwrap_err(), RawBlockError::RpcBudgetExceeded);
}

#[tokio::test]
async fn incomplete_http_and_content_encoding_are_never_success() {
    for (wire, expected) in [
        (Wire::Truncated(reply(1, json!(display_hash(0)))), RawBlockError::Transport),
        (Wire::Encoded, RawBlockError::MalformedResponse),
        (Wire::Status(503, format!("https://example.invalid/?{SENTINEL}")), RawBlockError::HttpStatus(503)),
    ] {
        let fixture = Fixture::start(vec![hash_step(wire)]);
        let error = client(&fixture).read_block(0, &mut Vec::new(), 1692).await.unwrap_err();
        assert_eq!(error, expected);
        assert!(!format!("{error:?}: {error}").contains(SENTINEL));
    }
}

#[tokio::test]
async fn redirect_to_second_listener_is_not_followed_or_leaked() {
    let trap = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    trap.set_nonblocking(true).unwrap();
    let location = format!("http://{}/private?{SENTINEL}", trap.local_addr().unwrap());
    for status in [302, 307, 308] {
        let fixture = Fixture::start(vec![hash_step(Wire::Status(status, location.clone()))]);
        let error = client(&fixture).read_block(0, &mut Vec::new(), 1692).await.unwrap_err();
        assert_eq!(error, RawBlockError::HttpStatus(status));
        assert_eq!(trap.accept().unwrap_err().kind(), std::io::ErrorKind::WouldBlock);
        assert_eq!(fixture.calls(), 1);
        assert!(!format!("{error:?}: {error}").contains(SENTINEL));
    }
    let fixture = Fixture::start(vec![hash_step(Wire::Status(302, format!("https://example.invalid/?{SENTINEL}")))]);
    assert_eq!(client(&fixture).read_block(0, &mut Vec::new(), 1692).await.unwrap_err(), RawBlockError::HttpStatus(302));
}

#[tokio::test]
async fn withheld_headers_body_and_slow_drip_obey_absolute_deadline() {
    for wire in [Wire::HoldHeaders, Wire::HoldBody, Wire::SlowChunks] {
        let fixture = Fixture::start(vec![hash_step(wire)]);
        let mut client = RawBlockClient::new(fixture.endpoint(), true, 1_000_000, Duration::from_millis(50)).unwrap();
        assert_eq!(client.read_block(0, &mut Vec::new(), 1692).await.unwrap_err(), RawBlockError::DeadlineExceeded);
    }
}

#[tokio::test]
async fn changed_final_hash_and_rpc_error_recheck_are_categorical_failures() {
    for (wire, expected) in [
        (Wire::Json(reply(3, json!(display_hash(1)))), RawBlockError::HashChanged),
        (Wire::Json(json!({"jsonrpc":"2.0", "id":3, "error":{"code":-8,"message":SENTINEL}})
            .to_string().into_bytes()), RawBlockError::RpcRejected(-8)),
    ] {
        let mut final_step = Step::hash(3, 0);
        final_step.wire = wire;
        let fixture = Fixture::start(vec![Step::hash(1, 0), Step::body(2, 0), final_step]);
        let mut client = client(&fixture);
        let acquired = client.read_block(0, &mut Vec::new(), 1692).await.unwrap();
        assert_eq!(client.recheck_hash(0, acquired).await.unwrap_err(), expected);
        assert_eq!(fixture.calls(), 3);
    }
}

#[tokio::test]
async fn expired_operation_recheck_does_not_issue_a_new_request() {
    let fixture = Fixture::start(Vec::new());
    let mut client = RawBlockClient::new(fixture.endpoint(), true, 1_000_000, Duration::from_millis(50)).unwrap();
    std::thread::sleep(Duration::from_millis(60));
    assert_eq!(client.recheck_hash(0, hash(0)).await.unwrap_err(), RawBlockError::DeadlineExceeded);
    assert_eq!(fixture.calls(), 0);
}

#[test]
fn invalid_endpoints_and_nonpositive_limits_are_rejected_locally_and_redacted() {
    for endpoint in ["http://localhost/rpc", "http://192.168.1.2/rpc", "http://2130706433/rpc",
        "http://0177.0.0.1/rpc", "http://0x7f000001/rpc", "ftp://127.0.0.1/rpc",
        "https://user:password@example.invalid/", "https://@example.invalid/rpc", "https://example.invalid/#private",
        "https:///example.invalid/", "http:127.0.0.1", "https:\\example.invalid", " https://example.invalid/",
        "https://example.invalid/\n", "http://evil.invalid/?http://127.0.0.1"] {
        assert_eq!(RawBlockClient::new(endpoint, true, 1, Duration::from_secs(1)).unwrap_err(), RawBlockError::InvalidEndpoint);
    }
    assert_eq!(RawBlockClient::new("http://127.0.0.1/rpc", false, 1, Duration::from_secs(1)).unwrap_err(), RawBlockError::InvalidEndpoint);
    for (bytes, elapsed) in [(0, Duration::from_secs(1)), (1, Duration::ZERO), (1, Duration::MAX)] {
        assert_eq!(RawBlockClient::new("http://127.0.0.1/rpc", true, bytes, elapsed).unwrap_err(), RawBlockError::InvalidPolicy);
    }
    for endpoint in ["https://example.invalid/rpc?private", "http://[::1]/rpc"] {
        assert!(RawBlockClient::new(endpoint, true, 1, Duration::from_secs(1)).is_ok());
    }
}

#[tokio::test]
async fn transport_failure_and_zero_body_limit_do_not_expose_endpoint() {
    let fixture = Fixture::start(Vec::new());
    assert_eq!(client(&fixture).read_block(0, &mut Vec::new(), 0).await.unwrap_err(), RawBlockError::InvalidPolicy);
    assert_eq!(fixture.calls(), 0);
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let address = listener.local_addr().unwrap();
    drop(listener);
    let mut client = RawBlockClient::new(&format!("http://{address}/rpc?{SENTINEL}"), true,
        1_000_000, Duration::from_secs(5)).unwrap();
    let error = client.read_block(0, &mut Vec::new(), 1692).await.unwrap_err();
    assert_eq!(error, RawBlockError::Transport);
    assert!(!format!("{client:?} {error:?}: {error}").contains(SENTINEL));
}
