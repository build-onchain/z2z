//! Synthetic-only PostgreSQL inventory demonstration. It does not import old
//! funded journals, move assets or prove source/destination settlement.
//!
//! Configure the private URI through Z2Z_TEST_DATABASE_URL, plus authorized test
//! schema prefix/opt-in configuration used by postgres-tests. Never pass a URI
//! on argv. Supply one NEW authorized schema and explicit synthetic scope IDs:
//! inventory --initialize-synthetic SCHEMA ACTOR_HEX ASSET_HEX DEPLOYMENT_HEX

use primitive_types::U256;
use std::{error::Error, io};
use ziquid_protocol::NativeAmount;
use ziquid_runtime::{
    database::{self, DatabaseConfig, DatabaseError},
    store::{ActorStore, FundingState, InventoryScope, StoreError},
};

fn id(text: &str) -> Result<[u8; 32], io::Error> {
    if text.len() != 64 || !text.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err(io::Error::other("scope IDs must be exactly 64 hexadecimal characters"));
    }
    let mut id = [0; 32];
    for (byte, pair) in id.iter_mut().zip(text.as_bytes().as_chunks::<2>().0) {
        let high = char::from(pair[0]).to_digit(16).unwrap();
        let low = char::from(pair[1]).to_digit(16).unwrap();
        *byte = ((high << 4) | low) as u8;
    }
    Ok(id)
}

#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<(), Box<dyn Error>> {
    let arguments = std::env::args().skip(1).collect::<Vec<_>>();
    let [flag, schema, actor, asset, deployment] = arguments.as_slice() else {
        return Err::<(), Box<dyn Error>>(io::Error::other(
            "usage: inventory --initialize-synthetic NEW_AUTHORIZED_SCHEMA ACTOR_HEX ASSET_HEX DEPLOYMENT_HEX; private URI only in Z2Z_TEST_DATABASE_URL"
        ).into());
    };
    if flag != "--initialize-synthetic" {
        return Err(io::Error::other("explicit synthetic schema initialization is required").into());
    }
    let config = DatabaseConfig {
        uri_env: "Z2Z_TEST_DATABASE_URL".into(), schema: schema.clone(), max_connections: 2,
    };
    config.validate()?;
    let scope = InventoryScope { actor: id(actor)?, asset: id(asset)?, deployment: id(deployment)? };
    // This demonstration is feature-gated and uses the same explicit schema
    // authorization as SQL tests, not an unrestricted production/admin pool.
    let mut inspection = database::test_connection(&config).await?;
    let exists: bool = sqlx::query_scalar(
        "SELECT EXISTS(SELECT 1 FROM pg_catalog.pg_namespace WHERE nspname = $1)"
    ).bind(&config.schema).fetch_one(&mut inspection).await.map_err(DatabaseError::from)?;
    drop(inspection);
    if exists {
        return Err(io::Error::other("synthetic demonstration requires a new schema; existing inventory remains untouched").into());
    }
    let amount = NativeAmount::new(U256::from(7));
    let capacity = NativeAmount::new(U256::from(10));
    let mut store = ActorStore::connect(config.clone(), scope).await?;
    store.migrate().await?;
    store.reserve([1; 32], [2; 32], amount, capacity).await?;
    store.prepare_funding([1; 32], [3; 32], [4; 32]).await?;
    store.mark_submission_unknown([3; 32], [5; 32]).await?;
    drop(store);
    let mut reopened = ActorStore::connect(config, scope).await?;
    let funding = reopened.funding([3; 32]).await?
        .ok_or_else(|| io::Error::other("funding intent lost"))?;
    if funding.state != FundingState::SubmissionUnknown
        || !matches!(reopened.cancel([1; 32]).await, Err(StoreError::FundingFenced))
    {
        return Err(io::Error::other("unknown funding did not retain its fence").into());
    }
    println!(
        "durable_funding=SubmissionUnknown reconnect=preserved cancellation=fenced amount_wei=7 scope=explicit_synthetic_accounting_only"
    );
    Ok(())
}
