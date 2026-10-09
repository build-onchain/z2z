//! Shared concrete endpoint/transport policy; no RPC/provider abstraction.

use std::{net::IpAddr, time::Duration};
use url::{Host, Url};

pub(crate) enum HttpClientError {
    InvalidEndpoint,
    Transport,
}

pub(crate) fn client(
    endpoint: &str, allow_loopback_http: bool, timeout: Duration,
) -> Result<(Url, reqwest::Client), HttpClientError> {
    if endpoint.chars().any(|character| character.is_whitespace() || character.is_control()) {
        return Err(HttpClientError::InvalidEndpoint);
    }
    // The delimiter must follow the actual leading scheme, never a URL embedded
    // in a path/query that WHATWG parsing would normalize away.
    let (scheme, rest) = endpoint.split_once("://").ok_or(HttpClientError::InvalidEndpoint)?;
    if !scheme.eq_ignore_ascii_case("https") && !scheme.eq_ignore_ascii_case("http") {
        return Err(HttpClientError::InvalidEndpoint);
    }
    let raw_authority = rest.split(['/', '?', '#']).next().unwrap_or("");
    let endpoint = Url::parse(endpoint).map_err(|_| HttpClientError::InvalidEndpoint)?;
    let raw_host = if raw_authority.starts_with('[') {
        raw_authority.split_once(']').map_or("", |(host, _)| &host[1..])
    } else { raw_authority.split(':').next().unwrap_or("") };
    let loopback = raw_host.parse::<IpAddr>().is_ok_and(|ip| {
        ip.is_loopback() && match (ip, endpoint.host()) {
            (IpAddr::V4(raw), Some(Host::Ipv4(parsed))) => raw == parsed,
            (IpAddr::V6(raw), Some(Host::Ipv6(parsed))) => raw == parsed,
            _ => false,
        }
    });
    if endpoint.host().is_none() || raw_authority.is_empty() || raw_authority.contains('@')
        || !endpoint.username().is_empty() || endpoint.password().is_some()
        || endpoint.fragment().is_some()
        || !(endpoint.scheme() == "https"
            || (endpoint.scheme() == "http" && allow_loopback_http && loopback))
    {
        return Err(HttpClientError::InvalidEndpoint);
    }
    let timeout = timeout.min(Duration::from_secs(30));
    let client = reqwest::Client::builder()
        .https_only(endpoint.scheme() == "https")
        .redirect(reqwest::redirect::Policy::none())
        .retry(reqwest::retry::never())
        .pool_max_idle_per_host(0)
        .no_proxy()
        .no_gzip().no_brotli().no_zstd().no_deflate()
        .connect_timeout(timeout.min(Duration::from_secs(10)))
        .timeout(timeout)
        .build().map_err(|_| HttpClientError::Transport)?;
    Ok((endpoint, client))
}
