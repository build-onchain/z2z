use super::{Error, Result};
use crate::{
    database::DatabaseConfig,
    market::ledger::{MAX_JOURNAL_BYTES, PairPolicy},
};
use ziquid_protocol::market::{Domain, Id, ObservationEnvironment};
use serde::{Deserialize, Serialize};
use std::{
    fs::File,
    io::Read,
    path::{Path, PathBuf},
};

/// Nonsecret transport only; connection policy resolves credentials privately.
#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Database {
    pub uri_env: String,
    pub schema: String,
    pub max_connections: u32,
}
impl Database {
    pub fn config(&self) -> Result<DatabaseConfig> {
        let config = DatabaseConfig {
            uri_env: self.uri_env.clone(),
            schema: self.schema.clone(),
            max_connections: self.max_connections,
        };
        config.validate().map_err(|_| Error::Configuration)?;
        Ok(config)
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StoreConfig {
    pub schema_version: u16,
    pub database: Database,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReplicaConfig {
    pub schema_version: u16,
    pub database: Database,
    pub policy: Vec<u8>,
    pub expected_signer: Id,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CoordinatorConfig {
    pub schema_version: u16,
    pub database: Database,
    pub policy: Vec<u8>,
    pub replicas: Vec<PathBuf>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LocalConfig {
    pub schema_version: u16,
    pub environment: String,
    pub database: Database,
    pub replicas: [Database; 3],
    pub solana_binary: PathBuf,
    pub solana_elf: PathBuf,
    pub native_policy: PathBuf,
}

pub fn read<T: serde::de::DeserializeOwned>(path: &Path) -> Result<T> {
    serde_json::from_slice(&read_bytes(path, MAX_JOURNAL_BYTES)?).map_err(|_| Error::Configuration)
}

pub fn read_bytes(path: &Path, maximum: usize) -> Result<Vec<u8>> {
    let file = File::open(path).map_err(|_| Error::Input)?;
    if file.metadata().map_err(|_| Error::Input)?.len() > maximum as u64 {
        return Err(Error::Input);
    }
    let mut bytes = Vec::new();
    file.take(maximum as u64 + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| Error::Input)?;
    if bytes.len() > maximum {
        return Err(Error::Input);
    }
    Ok(bytes)
}

pub fn version(version: u16) -> Result<()> {
    if version == 1 {
        Ok(())
    } else {
        Err(Error::Configuration)
    }
}

pub fn policy(bytes: &[u8]) -> Result<PairPolicy> {
    let policy = PairPolicy::decode(bytes)?;
    policy.domain.validate().map_err(|_| Error::Configuration)?;
    if policy.inventory_scope != policy.domain.pair {
        return Err(Error::Configuration);
    }
    Ok(policy)
}

pub fn environment(value: &str) -> Result<ObservationEnvironment> {
    match value {
        "LocalFixture" => Ok(ObservationEnvironment::LocalFixture),
        "Network" => Ok(ObservationEnvironment::Network),
        _ => Err(Error::Configuration),
    }
}

pub fn domain(bytes: &[u8]) -> Result<Domain> {
    Domain::decode(bytes).map_err(|_| Error::Configuration)
}
