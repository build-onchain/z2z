//! Shared PostgreSQL transport and schema policy; this module is not money authority.

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use sqlx::{ConnectOptions, PgConnection, PgPool, Postgres, Row, Transaction};
#[cfg(feature = "postgres-tests")]
use sqlx::Connection;
use sqlx::migrate::Migrator;
use sqlx::postgres::{PgConnectOptions, PgPoolOptions, PgSslMode};
use std::collections::HashSet;
use std::time::{Duration, Instant};
use zeroize::Zeroizing;

/// Child-process configuration carries a reference to a secret, never the secret.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DatabaseConfig {
    pub uri_env: String,
    pub schema: String,
    pub max_connections: u32,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DatabaseError {
    InvalidConfig, MissingUri, InvalidUri, UnsupportedParameter, InsecureTransport,
    Connection, SchemaIdentity, SchemaNotReady, Migration, Query,
}
impl std::fmt::Display for DatabaseError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::InvalidConfig => "invalid database configuration",
            Self::MissingUri => "private database configuration is unavailable",
            Self::InvalidUri => "invalid private database connection policy",
            Self::UnsupportedParameter => "unsupported private database parameter",
            Self::InsecureTransport => "database transport requires verified TLS",
            Self::Connection => "database connection failed",
            Self::SchemaIdentity => "database schema identity rejected",
            Self::SchemaNotReady => "database schema migration is required",
            Self::Migration => "database migration failed",
            Self::Query => "database operation failed",
        })
    }
}
impl std::error::Error for DatabaseError {}
impl From<sqlx::Error> for DatabaseError {
    fn from(_: sqlx::Error) -> Self { Self::Query }
}

fn identifier(name: &str) -> bool {
    !name.is_empty() && name.len() <= 63 && name.as_bytes()[0].is_ascii_lowercase()
        && name.bytes().all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_')
        && !name.starts_with("pg_") && name != "public"
}
impl DatabaseConfig {
    pub fn validate(&self) -> Result<(), DatabaseError> {
        let mut env = self.uri_env.bytes();
        let first = env.next().is_some_and(|b| b.is_ascii_alphabetic() || b == b'_');
        if !identifier(&self.schema) || self.max_connections == 0 || !first
            || !env.all(|b| b.is_ascii_alphanumeric() || b == b'_') {
            return Err(DatabaseError::InvalidConfig);
        }
        Ok(())
    }
}

fn decoded(value: &str, plus: bool) -> Result<String, DatabaseError> {
    let mut bytes = Vec::with_capacity(value.len());
    let mut input = value.bytes();
    while let Some(byte) = input.next() {
        bytes.push(match byte {
            b'%' => {
                let high = input.next().and_then(|b| char::from(b).to_digit(16));
                let low = input.next().and_then(|b| char::from(b).to_digit(16));
                match (high, low) { (Some(h), Some(l)) => ((h << 4) | l) as u8, _ => return Err(DatabaseError::InvalidUri) }
            }
            b'+' if plus => b' ',
            other => other,
        });
    }
    let text = String::from_utf8(bytes).map_err(|_| DatabaseError::InvalidUri)?;
    if text.chars().any(char::is_control) { return Err(DatabaseError::InvalidUri); }
    Ok(text)
}

// SQLx's FromStr warns with unknown decoded key/value pairs. Never call that
// parser: validate all decoded parameters before constructing private options.
fn validated_options(uri: &str, config: &DatabaseConfig) -> Result<PgConnectOptions, DatabaseError> {
    config.validate()?;
    if uri.chars().any(char::is_control) { return Err(DatabaseError::InvalidUri); }
    let url = url::Url::parse(uri).map_err(|_| DatabaseError::InvalidUri)?;
    if !matches!(url.scheme(), "postgres" | "postgresql") || url.fragment().is_some() {
        return Err(DatabaseError::InvalidUri);
    }
    let host = url.host_str().ok_or(DatabaseError::InsecureTransport)?;
    let host_decoded = decoded(host, false)?;
    if host.is_empty() || host_decoded.starts_with('/') || host.contains('%') || url.port() == Some(0) {
        return Err(DatabaseError::InsecureTransport);
    }
    let username = decoded(url.username(), false)?;
    let password = Zeroizing::new(decoded(url.password().ok_or(DatabaseError::InvalidUri)?, false)?);
    let database = decoded(url.path().strip_prefix('/').ok_or(DatabaseError::InvalidUri)?, false)?;
    if username.is_empty() || password.is_empty() || database.is_empty() || database.contains('/') {
        return Err(DatabaseError::InvalidUri);
    }
    let mut seen = HashSet::new();
    let mut root = None;
    let mut cert = None;
    let mut key_path = None;
    let mut cache = 100;
    if let Some(query) = url.query() {
        for part in query.split('&') {
            let (raw_key, raw_value) = part.split_once('=').ok_or(DatabaseError::InvalidUri)?;
            let key = decoded(raw_key, true)?;
            let value = Zeroizing::new(decoded(raw_value, true)?);
            let canonical = match key.as_str() {
                "sslmode" | "ssl-mode" => "sslmode",
                "sslrootcert" | "ssl-root-cert" | "ssl-ca" => "sslrootcert",
                "sslcert" | "ssl-cert" => "sslcert",
                "sslkey" | "ssl-key" => "sslkey",
                "statement-cache-capacity" => "statement-cache-capacity",
                _ => return Err(DatabaseError::UnsupportedParameter),
            };
            if !seen.insert(canonical) { return Err(DatabaseError::UnsupportedParameter); }
            match canonical {
                "sslmode" if value.as_str() != "verify-full" => return Err(DatabaseError::InsecureTransport),
                "sslmode" => {},
                "statement-cache-capacity" => cache = value.parse::<usize>().map_err(|_| DatabaseError::InvalidUri)?,
                _ => {
                    if !std::path::Path::new(value.as_str()).is_absolute() || value.contains("-----BEGIN") {
                        return Err(DatabaseError::InvalidUri);
                    }
                    match canonical {
                        "sslrootcert" => root = Some(value.to_string()),
                        "sslcert" => cert = Some(value.to_string()),
                        _ => key_path = Some(value.to_string()),
                    }
                }
            }
        }
    }
    if cert.is_some() != key_path.is_some() { return Err(DatabaseError::InvalidUri); }
    // SQLx initializes from libpq environment even in new_without_pgpass.
    // Explicit URI credentials must be the only source of private transport/session settings.
    if ["PGHOST", "PGHOSTADDR", "PGPORT", "PGUSER", "PGPASSWORD", "PGDATABASE", "PGOPTIONS",
        "PGSSLMODE", "PGSSLROOTCERT", "PGSSLCERT", "PGSSLKEY", "PGAPPNAME", "PGPASSFILE"]
        .iter().any(|name| std::env::var_os(name).is_some()) {
        return Err(DatabaseError::InvalidConfig);
    }
    let path = format!("\"{}\",pg_temp", config.schema);
    let host = host.strip_prefix('[').and_then(|v| v.strip_suffix(']')).unwrap_or(host);
    let mut options = PgConnectOptions::new_without_pgpass()
        .host(host).port(url.port().unwrap_or(5432)).username(&username).password(&password)
        .database(&database).ssl_mode(PgSslMode::VerifyFull).statement_cache_capacity(cache)
        .application_name("z2z-runtime").options([("search_path", path.as_str()), ("synchronous_commit", "on"), ("client_min_messages", "error")])
        .disable_statement_logging();
    if let Some(path) = root { options = options.ssl_root_cert(path); }
    if let Some(path) = cert { options = options.ssl_client_cert(path); }
    if let Some(path) = key_path { options = options.ssl_client_key(path); }
    Ok(options)
}

fn private_options(config: &DatabaseConfig) -> Result<PgConnectOptions, DatabaseError> {
    config.validate()?;
    let uri = Zeroizing::new(std::env::var(&config.uri_env).map_err(|_| DatabaseError::MissingUri)?);
    validated_options(&uri, config)
}

#[derive(Clone, Copy)]
pub(crate) struct SchemaSpec {
    pub application: &'static str,
    pub version: i32,
    pub relations: &'static [&'static str],
    pub domains: &'static [&'static str],
    pub functions: &'static [&'static str],
}

fn hook_error(_: DatabaseError) -> sqlx::Error {
    // Pool hooks log errors internally. Never hand them a raw server error.
    sqlx::Error::Protocol("database session policy rejected".into())
}

// The selected role/server administrator is trusted to retain committed records
// and not rewrite catalogs/identity during an operation. Metadata authentication
// here detects drift, not a malicious database owner capable of forging it.
// ponytail: full schema fingerprint on each acquisition bounds throughput;
// use a separately authorized immutable-schema role before caching this check.
pub(crate) async fn connect(config: &DatabaseConfig) -> Result<PgPool, DatabaseError> {
    let options = private_options(config)?;
    let fresh = config.clone();
    let reused = config.clone();
    let pool = PgPoolOptions::new().max_connections(config.max_connections)
        .acquire_timeout(Duration::from_secs(10)).test_before_acquire(false)
        .after_connect(move |connection, _| {
            let config = fresh.clone();
            Box::pin(async move { session(connection, &config).await.map_err(hook_error) })
        })
        .before_acquire(move |connection, _| {
            let config = reused.clone();
            Box::pin(async move {
                match session(connection, &config).await {
                    Ok(()) => Ok(true),
                    // A policy rejection is not a broken transport. Return false so SQLx
                    // sends Terminate before TLS shutdown instead of hard-closing idle TLS.
                    Err(DatabaseError::SchemaIdentity) => Ok(false),
                    Err(error) => Err(hook_error(error)),
                }
            })
        })
        .connect_with(options).await.map_err(|_| DatabaseError::Connection)?;
    Ok(pool)
}

async fn session(connection: &mut PgConnection, config: &DatabaseConfig) -> Result<(), DatabaseError> {
    sqlx::query("SELECT pg_catalog.set_config('search_path',$1,false), pg_catalog.set_config('synchronous_commit','on',false), pg_catalog.set_config('client_min_messages','error',false)")
        .bind(format!("\"{}\",pg_temp", config.schema)).execute(&mut *connection).await?;
    inspect(connection, config, None, true).await.map(|_| ())
}

fn digest_rows(rows: impl IntoIterator<Item = String>) -> Vec<u8> {
    let mut digest = Sha256::new();
    for row in rows { digest.update((row.len() as u64).to_be_bytes()); digest.update(row.as_bytes()); }
    digest.finalize().to_vec()
}

async fn catalog(connection: &mut PgConnection, schema: &str) -> Result<Vec<String>, DatabaseError> {
    // PostgreSQL's internal "char" needs an explicit text cast to disambiguate ||.
    sqlx::query_scalar::<_, String>(r#"
        SELECT entry FROM (
          SELECT 'relation:'||c.relname||':'||c.relkind::text||':'||c.relowner::text||':'||c.relpersistence::text||':'||c.relrowsecurity::text||':'||c.relforcerowsecurity::text AS entry
            FROM pg_catalog.pg_class c JOIN pg_catalog.pg_namespace n ON n.oid=c.relnamespace WHERE n.nspname=$1
          UNION ALL SELECT 'column:'||c.relname||':'||a.attnum::text||':'||a.attname||':'||a.atttypid::text||':'||a.atttypmod::text||':'||a.attnotnull::text||':'||a.attisdropped::text||':'||COALESCE(pg_catalog.pg_get_expr(d.adbin,d.adrelid),'')
            FROM pg_catalog.pg_attribute a JOIN pg_catalog.pg_class c ON c.oid=a.attrelid JOIN pg_catalog.pg_namespace n ON n.oid=c.relnamespace LEFT JOIN pg_catalog.pg_attrdef d ON d.adrelid=a.attrelid AND d.adnum=a.attnum WHERE n.nspname=$1 AND a.attnum>0
          UNION ALL SELECT 'constraint:'||co.conname||':'||co.conrelid::text||':'||co.contypid::text||':'||co.convalidated::text||':'||pg_catalog.pg_get_constraintdef(co.oid)
            FROM pg_catalog.pg_constraint co JOIN pg_catalog.pg_namespace n ON n.oid=co.connamespace WHERE n.nspname=$1
          UNION ALL SELECT 'index:'||i.indexrelid::text||':'||i.indisvalid::text||':'||i.indisready::text||':'||pg_catalog.pg_get_indexdef(i.indexrelid)
            FROM pg_catalog.pg_index i JOIN pg_catalog.pg_class c ON c.oid=i.indexrelid JOIN pg_catalog.pg_namespace n ON n.oid=c.relnamespace WHERE n.nspname=$1
          UNION ALL SELECT 'trigger:'||t.tgrelid::text||':'||t.tgname||':'||t.tgenabled::text||':'||pg_catalog.pg_get_triggerdef(t.oid)
            FROM pg_catalog.pg_trigger t JOIN pg_catalog.pg_class c ON c.oid=t.tgrelid JOIN pg_catalog.pg_namespace n ON n.oid=c.relnamespace WHERE n.nspname=$1 AND NOT t.tgisinternal
          UNION ALL SELECT 'policy:'||p.polrelid::text||':'||p.polname||':'||p.polcmd::text||':'||p.polpermissive::text||':'||p.polroles::text||':'||COALESCE(pg_catalog.pg_get_expr(p.polqual,p.polrelid),'')||':'||COALESCE(pg_catalog.pg_get_expr(p.polwithcheck,p.polrelid),'')
            FROM pg_catalog.pg_policy p JOIN pg_catalog.pg_class c ON c.oid=p.polrelid JOIN pg_catalog.pg_namespace n ON n.oid=c.relnamespace WHERE n.nspname=$1
          UNION ALL SELECT 'rewrite:'||r.ev_class::text||':'||r.rulename||':'||r.ev_type::text||':'||r.ev_enabled::text||':'||r.is_instead::text||':'||pg_catalog.pg_get_ruledef(r.oid)
            FROM pg_catalog.pg_rewrite r JOIN pg_catalog.pg_class c ON c.oid=r.ev_class JOIN pg_catalog.pg_namespace n ON n.oid=c.relnamespace WHERE n.nspname=$1
          UNION ALL SELECT 'type:'||t.typname||':'||t.typtype::text||':'||t.typowner::text||':'||t.typbasetype::text||':'||t.typtypmod::text||':'||t.typnotnull::text
            FROM pg_catalog.pg_type t JOIN pg_catalog.pg_namespace n ON n.oid=t.typnamespace WHERE n.nspname=$1
          UNION ALL SELECT 'function:'||p.proname||':'||p.proowner::text||':'||p.prosecdef::text||':'||COALESCE(p.proconfig::text,'')||':'||pg_catalog.pg_get_functiondef(p.oid)
            FROM pg_catalog.pg_proc p JOIN pg_catalog.pg_namespace n ON n.oid=p.pronamespace WHERE n.nspname=$1
        ) objects ORDER BY entry
    "#).bind(schema).fetch_all(connection).await.map_err(Into::into)
}

async fn namespace(connection: &mut PgConnection, schema: &str) -> Result<Option<i64>, DatabaseError> {
    let temporary: bool = sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM pg_catalog.pg_class WHERE relnamespace=pg_catalog.pg_my_temp_schema()) OR EXISTS(SELECT 1 FROM pg_catalog.pg_type WHERE typnamespace=pg_catalog.pg_my_temp_schema())")
        .fetch_one(&mut *connection).await?;
    if temporary { return Err(DatabaseError::SchemaIdentity); }
    // Current application schemas have no RLS or rewrite mechanism. Reject
    // money-affecting drift before even reading their marker/history relations.
    let redirected: bool = sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM pg_catalog.pg_class c JOIN pg_catalog.pg_namespace n ON n.oid=c.relnamespace WHERE n.nspname=$1 AND (c.relrowsecurity OR c.relforcerowsecurity)) OR EXISTS(SELECT 1 FROM pg_catalog.pg_policy p JOIN pg_catalog.pg_class c ON c.oid=p.polrelid JOIN pg_catalog.pg_namespace n ON n.oid=c.relnamespace WHERE n.nspname=$1) OR EXISTS(SELECT 1 FROM pg_catalog.pg_rewrite r JOIN pg_catalog.pg_class c ON c.oid=r.ev_class JOIN pg_catalog.pg_namespace n ON n.oid=c.relnamespace WHERE n.nspname=$1)")
        .bind(schema).fetch_one(&mut *connection).await?;
    if redirected { return Err(DatabaseError::SchemaIdentity); }
    let row = sqlx::query("SELECT n.oid::bigint AS oid,n.nspowner=(SELECT oid FROM pg_catalog.pg_roles WHERE rolname=current_user) AS owned,session_user=current_user AS direct FROM pg_catalog.pg_namespace n WHERE n.nspname=$1")
        .bind(schema).fetch_optional(connection).await?;
    row.map(|row| {
        if !row.try_get::<bool,_>("owned")? || !row.try_get::<bool,_>("direct")? { return Err(DatabaseError::SchemaIdentity); }
        row.try_get("oid").map_err(Into::into)
    }).transpose()
}

async fn history(connection: &mut PgConnection, schema: &str) -> Result<(i32, Vec<u8>), DatabaseError> {
    let rows = sqlx::query(&format!("SELECT version,description,success,checksum FROM \"{schema}\"._sqlx_migrations ORDER BY version"))
        .fetch_all(connection).await?;
    let mut encoded = Vec::with_capacity(rows.len());
    for (index, row) in rows.iter().enumerate() {
        let version: i64 = row.try_get("version")?;
        let checksum: Vec<u8> = row.try_get("checksum")?;
        if version != index as i64 + 1 || !row.try_get::<bool,_>("success")? || checksum.len() != 48 {
            return Err(DatabaseError::SchemaIdentity);
        }
        encoded.push(format!("{version}:{}:{checksum:?}", row.try_get::<String,_>("description")?));
    }
    Ok((i32::try_from(rows.len()).map_err(|_| DatabaseError::SchemaIdentity)?, digest_rows(encoded)))
}

async fn inspect(connection: &mut PgConnection, config: &DatabaseConfig, spec: Option<SchemaSpec>, allow_missing: bool) -> Result<bool, DatabaseError> {
    let Some(oid) = namespace(connection, &config.schema).await? else {
        return if allow_missing { Ok(false) } else { Err(DatabaseError::SchemaNotReady) };
    };
    let marker: bool = sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM pg_catalog.pg_class c JOIN pg_catalog.pg_namespace n ON n.oid=c.relnamespace WHERE n.nspname=$1 AND c.relname='_z2z_schema_identity' AND c.relkind='r' AND c.relpersistence='p')")
        .bind(&config.schema).fetch_one(&mut *connection).await?;
    if !marker { return Err(DatabaseError::SchemaIdentity); }
    let rows = sqlx::query(&format!("SELECT format,application,version,schema_oid,owner_oid,manifest,catalog_digest,migration_digest FROM \"{}\"._z2z_schema_identity", config.schema))
        .fetch_all(&mut *connection).await.map_err(|_| DatabaseError::SchemaIdentity)?;
    if rows.len() != 1 { return Err(DatabaseError::SchemaIdentity); }
    let row = &rows[0];
    let owner: i64 = sqlx::query_scalar("SELECT oid::bigint FROM pg_catalog.pg_roles WHERE rolname=current_user").fetch_one(&mut *connection).await?;
    let application: String = row.try_get("application")?;
    let version: i32 = row.try_get("version")?;
    if row.try_get::<i32,_>("format")? != 1 || row.try_get::<i64,_>("schema_oid")? != oid || row.try_get::<i64,_>("owner_oid")? != owner {
        return Err(DatabaseError::SchemaIdentity);
    }
    if let Some(spec) = spec {
        if application != spec.application || version != spec.version || row.try_get::<Vec<u8>,_>("manifest")? != manifest(spec)? {
            return Err(DatabaseError::SchemaIdentity);
        }
    } else if !matches!(application.as_str(), "market" | "inventory" | "samechain" | "native") { return Err(DatabaseError::SchemaIdentity); }
    if row.try_get::<Vec<u8>,_>("catalog_digest")? != digest_rows(catalog(connection, &config.schema).await?) {
        return Err(DatabaseError::SchemaIdentity);
    }
    let (applied, digest) = history(connection, &config.schema).await?;
    if applied != version || row.try_get::<Vec<u8>,_>("migration_digest")? != digest { return Err(DatabaseError::SchemaIdentity); }
    Ok(true)
}

fn manifest(spec: SchemaSpec) -> Result<Vec<u8>, DatabaseError> {
    if !identifier(spec.application) || spec.version < 1
        || spec.relations.iter().chain(spec.domains).chain(spec.functions).any(|name| !identifier(name)) {
        return Err(DatabaseError::InvalidConfig);
    }
    Ok(digest_rows(std::iter::once(format!("{}:{}", spec.application, spec.version))
        .chain(spec.relations.iter().map(|s| format!("table:{s}")))
        .chain(spec.domains.iter().map(|s| format!("domain:{s}")))
        .chain(spec.functions.iter().map(|s| format!("function:{s}")))))
}

async fn shape(connection: &mut PgConnection, config: &DatabaseConfig, spec: SchemaSpec) -> Result<(), DatabaseError> {
    for table in spec.relations.iter().copied().chain(["_sqlx_migrations", "_z2z_schema_identity"]) {
        let valid: bool = sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM pg_catalog.pg_class c JOIN pg_catalog.pg_namespace n ON n.oid=c.relnamespace WHERE n.nspname=$1 AND c.relname=$2 AND c.relkind='r' AND c.relpersistence='p' AND NOT c.relrowsecurity AND NOT c.relforcerowsecurity AND c.relowner=(SELECT oid FROM pg_catalog.pg_roles WHERE rolname=current_user))")
            .bind(&config.schema).bind(table).fetch_one(&mut *connection).await?;
        if !valid { return Err(DatabaseError::SchemaIdentity); }
    }
    let tables: i64 = sqlx::query_scalar("SELECT count(*) FROM pg_catalog.pg_class c JOIN pg_catalog.pg_namespace n ON n.oid=c.relnamespace WHERE n.nspname=$1 AND c.relkind NOT IN ('i','I')")
        .bind(&config.schema).fetch_one(&mut *connection).await?;
    if tables != spec.relations.len() as i64 + 2 { return Err(DatabaseError::SchemaIdentity); }
    for domain in spec.domains {
        let valid: bool = sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM pg_catalog.pg_type t JOIN pg_catalog.pg_namespace n ON n.oid=t.typnamespace WHERE n.nspname=$1 AND t.typname=$2 AND t.typtype='d' AND t.typowner=(SELECT oid FROM pg_catalog.pg_roles WHERE rolname=current_user))")
            .bind(&config.schema).bind(*domain).fetch_one(&mut *connection).await?;
        if !valid { return Err(DatabaseError::SchemaIdentity); }
    }
    let domains: i64 = sqlx::query_scalar("SELECT count(*) FROM pg_catalog.pg_type t JOIN pg_catalog.pg_namespace n ON n.oid=t.typnamespace WHERE n.nspname=$1 AND t.typtype NOT IN ('c','b')")
        .bind(&config.schema).fetch_one(&mut *connection).await?;
    let functions: Vec<String> = sqlx::query_scalar("SELECT p.proname::text FROM pg_catalog.pg_proc p JOIN pg_catalog.pg_namespace n ON n.oid=p.pronamespace WHERE n.nspname=$1 AND p.proowner=(SELECT oid FROM pg_catalog.pg_roles WHERE rolname=current_user) ORDER BY p.proname")
        .bind(&config.schema).fetch_all(&mut *connection).await?;
    let mut expected = spec.functions.iter().map(|v| (*v).to_owned()).collect::<Vec<_>>();
    expected.sort();
    if domains != spec.domains.len() as i64 || functions != expected { return Err(DatabaseError::SchemaIdentity); }
    Ok(())
}

pub(crate) async fn ensure_ready(pool: &PgPool, config: &DatabaseConfig, spec: SchemaSpec) -> Result<(), DatabaseError> {
    config.validate()?;
    let mut connection = pool.acquire().await.map_err(|_| DatabaseError::Connection)?;
    inspect(&mut connection, config, Some(spec), false).await?;
    Ok(())
}

/// Initialize only an absent schema. Original migration SQL and SHA384 checksums
/// remain exact; marker/history/DDL commit together under the schema lock.
pub(crate) async fn migrate(pool: &PgPool, config: &DatabaseConfig, spec: SchemaSpec, migrations: &Migrator) -> Result<(), DatabaseError> {
    config.validate()?;
    let manifest = manifest(spec)?;
    if migrations.iter().count() != spec.version as usize || migrations.iter().enumerate().any(|(i,m)| m.version != i as i64 + 1 || m.no_tx || m.migration_type.is_down_migration()) {
        return Err(DatabaseError::Migration);
    }
    let mut tx: Transaction<'_, Postgres> = pool.begin_with("BEGIN ISOLATION LEVEL READ COMMITTED").await.map_err(|_| DatabaseError::Connection)?;
    sqlx::query("SELECT pg_catalog.pg_advisory_xact_lock(pg_catalog.hashtextextended(current_database()||':'||$1,0))")
        .bind(&config.schema).execute(&mut *tx).await?;
    if namespace(&mut tx, &config.schema).await?.is_some() {
        inspect(&mut tx, config, Some(spec), false).await?;
        shape(&mut tx, config, spec).await?;
        let rows = sqlx::query(&format!("SELECT version,checksum FROM \"{}\"._sqlx_migrations ORDER BY version", config.schema)).fetch_all(&mut *tx).await?;
        for (row, migration) in rows.iter().zip(migrations.iter()) {
            if row.try_get::<i64,_>("version")? != migration.version || row.try_get::<Vec<u8>,_>("checksum")?.as_slice() != migration.checksum.as_ref() { return Err(DatabaseError::Migration); }
        }
        tx.commit().await?;
        return Ok(());
    }
    sqlx::raw_sql(&format!("CREATE SCHEMA \"{}\"; REVOKE ALL ON SCHEMA \"{}\" FROM PUBLIC; SET LOCAL search_path TO \"{}\",pg_temp; SET LOCAL synchronous_commit TO on", config.schema, config.schema, config.schema))
        .execute(&mut *tx).await.map_err(|_| DatabaseError::Migration)?;
    sqlx::raw_sql(&format!("CREATE TABLE \"{}\"._z2z_schema_identity (singleton BOOLEAN PRIMARY KEY CHECK(singleton),format INTEGER NOT NULL,application TEXT NOT NULL,version INTEGER NOT NULL,schema_oid BIGINT NOT NULL,owner_oid BIGINT NOT NULL,manifest BYTEA NOT NULL,catalog_digest BYTEA NOT NULL,migration_digest BYTEA NOT NULL); CREATE TABLE \"{}\"._sqlx_migrations (version BIGINT PRIMARY KEY,description TEXT NOT NULL,installed_on TIMESTAMPTZ NOT NULL DEFAULT now(),success BOOLEAN NOT NULL,checksum BYTEA NOT NULL,execution_time BIGINT NOT NULL)", config.schema, config.schema))
        .execute(&mut *tx).await.map_err(|_| DatabaseError::Migration)?;
    for migration in migrations.iter() {
        let start = Instant::now();
        sqlx::raw_sql(&migration.sql).execute(&mut *tx).await.map_err(|_| DatabaseError::Migration)?;
        sqlx::query(&format!("INSERT INTO \"{}\"._sqlx_migrations(version,description,success,checksum,execution_time) VALUES($1,$2,true,$3,$4)", config.schema))
            .bind(migration.version).bind(migration.description.as_ref()).bind(migration.checksum.as_ref())
            .bind(i64::try_from(start.elapsed().as_nanos()).unwrap_or(i64::MAX)).execute(&mut *tx).await?;
    }
    shape(&mut tx, config, spec).await?;
    let oid = namespace(&mut tx, &config.schema).await?.ok_or(DatabaseError::SchemaIdentity)?;
    let owner: i64 = sqlx::query_scalar("SELECT oid::bigint FROM pg_catalog.pg_roles WHERE rolname=current_user").fetch_one(&mut *tx).await?;
    let catalog = digest_rows(catalog(&mut tx, &config.schema).await?);
    let (_, history) = history(&mut tx, &config.schema).await?;
    sqlx::query(&format!("INSERT INTO \"{}\"._z2z_schema_identity VALUES(true,1,$1,$2,$3,$4,$5,$6,$7)", config.schema))
        .bind(spec.application).bind(spec.version).bind(oid).bind(owner).bind(manifest).bind(catalog).bind(history).execute(&mut *tx).await?;
    tx.commit().await.map_err(|_| DatabaseError::Migration)
}

#[cfg(feature = "postgres-tests")]
fn test_authorization(config: &DatabaseConfig) -> Result<(), DatabaseError> {
    config.validate()?;
    let prefix = std::env::var("Z2Z_TEST_PG_SCHEMA_PREFIX").map_err(|_| DatabaseError::InvalidConfig)?;
    if std::env::var("Z2Z_TEST_PG_ALLOW_SCHEMA_CHANGES").as_deref() != Ok("yes")
        || !identifier(&prefix) || prefix.len() > 30 || config.uri_env != "Z2Z_TEST_DATABASE_URL"
        || !config.schema.starts_with(&format!("{prefix}_")) { return Err(DatabaseError::InvalidConfig); }
    Ok(())
}

/// Only opt-in SQL fixtures can borrow an unrestricted connection. Never used
/// by production ledger/inventory APIs; authorization is checked before connect.
#[cfg(feature = "postgres-tests")]
#[doc(hidden)]
pub async fn test_connection(config: &DatabaseConfig) -> Result<PgConnection, DatabaseError> {
    test_authorization(config)?;
    PgConnection::connect_with(&private_options(config)?).await.map_err(|_| DatabaseError::Connection)
}

#[cfg(feature = "postgres-tests")]
#[doc(hidden)]
pub async fn test_drop_schema(config: &DatabaseConfig) -> Result<(), DatabaseError> {
    let mut connection = test_connection(config).await?;
    let suffix = config.schema.rsplit_once('_').ok_or(DatabaseError::InvalidConfig)?.1;
    if suffix.len() != 24 || !suffix.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err(DatabaseError::InvalidConfig);
    }
    if namespace(&mut connection, &config.schema).await?.is_some() {
        inspect(&mut connection, config, None, false).await?;
        sqlx::raw_sql(&format!("DROP SCHEMA \"{}\" CASCADE", config.schema)).execute(&mut connection).await?;
    }
    connection.close().await.map_err(|_| DatabaseError::Connection)
}

#[cfg(test)]
mod database_configuration {
    use super::*;
    use std::io::{self, Write};
    use std::sync::{Arc, Mutex};

    fn config() -> DatabaseConfig {
        DatabaseConfig { uri_env: "Z2Z_TEST_DATABASE_URL".into(), schema: "z2z_market_test".into(), max_connections: 4 }
    }

    #[test]
    fn configuration_rejects_invalid_identifiers_and_serializes_no_uri() {
        for schema in ["", "public", "pg_temp", "pg_catalog", "UPPER", "0first", "a-b", "a.b", "a,b", "a\"b", "ümlaut"] {
            let mut candidate = config();
            candidate.schema = schema.into();
            assert_eq!(candidate.validate(), Err(DatabaseError::InvalidConfig));
        }
        let mut candidate = config();
        candidate.schema = "a".repeat(64);
        assert_eq!(candidate.validate(), Err(DatabaseError::InvalidConfig));
        candidate.schema = "a".repeat(63);
        assert_eq!(candidate.validate(), Ok(()));
        candidate.max_connections = 0;
        assert_eq!(candidate.validate(), Err(DatabaseError::InvalidConfig));
        candidate = config();
        candidate.uri_env = "URI=credential".into();
        assert_eq!(candidate.validate(), Err(DatabaseError::InvalidConfig));
        assert!(serde_json::from_str::<DatabaseConfig>(r#"{"uri_env":"URI","schema":"z2z_test","max_connections":1,"uri":"secret"}"#).is_err());
    }

    #[test]
    fn decoded_unknown_parameters_and_aliases_fail_closed_before_sqlx() {
        let base = "postgresql://user:synthetic%3Apassword@db.example.invalid/market";
        for suffix in ["token=synthetic%2Fsecret", "%74oken=synthetic%2Fsecret", "options%5Bsearch_path%5D=public", "options=-c+role%3Dadmin", "password=secret", "host=%2Ftmp", "dbname=other", "sslmode=verify-full&ssl-mode=verify-full", "sslrootcert=%2Fca&ssl-ca=%2Fca", "token=%FF", "%GG=secret"] {
            assert!(validated_options(&format!("{base}?{suffix}"), &config()).is_err());
        }
        for suffix in ["sslmode=disable", "sslmode=prefer", "sslmode=require", "sslmode=verify-ca", "sslmode=allow"] {
            assert!(matches!(validated_options(&format!("{base}?{suffix}"), &config()), Err(DatabaseError::InsecureTransport)));
        }
        let options = validated_options(&format!("{base}?%73slmode=verify-full&sslrootcert=%2Fca.pem"), &config()).unwrap();
        assert_eq!(options.get_host(), "db.example.invalid");
        assert_eq!(options.get_database(), Some("market"));
        assert!(matches!(options.get_ssl_mode(), sqlx::postgres::PgSslMode::VerifyFull));
        assert!(options.get_socket().is_none());
    }

    #[test]
    fn absent_or_socket_authority_never_falls_back_to_local_transport() {
        for uri in ["postgres://", "postgres:///market", "postgres://user:secret@/market", "postgres://user:secret@%2Ftmp/market", "postgres://user@db.example.invalid/market", "postgres://user:secret@db.example.invalid/", "postgres://user:secret@db.example.invalid/market#secret", "https://user:secret@db.example.invalid/market", "postgres://user:secret@db.example.invalid:0/market"] {
            assert!(validated_options(uri, &config()).is_err());
        }
    }

    #[derive(Clone)]
    struct Capture(Arc<Mutex<Vec<u8>>>);
    impl Write for Capture {
        fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
            self.0.lock().unwrap_or_else(std::sync::PoisonError::into_inner).extend_from_slice(bytes);
            Ok(bytes.len())
        }
        fn flush(&mut self) -> io::Result<()> { Ok(()) }
    }

    #[test]
    fn unknown_secret_parameters_and_parse_errors_never_reach_tracing() {
        let bytes = Arc::new(Mutex::new(Vec::new()));
        let writer = Capture(bytes.clone());
        let subscriber = tracing_subscriber::fmt().with_ansi(false).without_time().with_writer(move || writer.clone()).finish();
        let uri = "postgres://user:synthetic-password@db.example.invalid/market?%74oken=synthetic-secret-param";
        tracing::subscriber::with_default(subscriber, || {
            assert!(matches!(validated_options(uri, &config()), Err(DatabaseError::UnsupportedParameter)));
            assert!(validated_options("postgres://user:secret@db.example.invalid/market?%GG=synthetic-secret-param", &config()).is_err());
        });
        let output = String::from_utf8(bytes.lock().unwrap_or_else(std::sync::PoisonError::into_inner).clone()).unwrap();
        for secret in [uri, "synthetic-password", "synthetic-secret-param"] { assert!(!output.contains(secret)); }
        assert!(output.is_empty(), "transport validation emitted diagnostics");
        for error in [DatabaseError::InvalidConfig, DatabaseError::MissingUri, DatabaseError::InvalidUri, DatabaseError::UnsupportedParameter, DatabaseError::InsecureTransport, DatabaseError::Connection, DatabaseError::SchemaIdentity, DatabaseError::SchemaNotReady, DatabaseError::Migration, DatabaseError::Query] {
            assert!(!format!("{error} {error:?}").contains("synthetic"));
        }
    }
}

#[cfg(all(test, feature = "postgres-tests"))]
mod postgres_schema_policy {
    use super::*;

    use crate::market_ledger_test_support as support;

    #[tokio::test]
    async fn temporary_history_relation_and_domain_are_rejected_before_business_or_migration_sql() {
        let db = support::TestDatabase::create("tempshadow").await;
        let pool = connect(&db.config).await.unwrap();
        let ledger = crate::market::ledger::Ledger::connect(&db.config).await.unwrap();
        ledger.migrate().await.unwrap(); ledger.close().await;
        let mut connection = pool.acquire().await.unwrap();
        sqlx::raw_sql("CREATE TEMP TABLE _sqlx_migrations(version BIGINT,checksum BYTEA); CREATE TEMP TABLE ledger_pairs(sentinel TEXT); CREATE DOMAIN pg_temp.kerb_id AS TEXT")
            .execute(&mut *connection).await.unwrap();
        assert_eq!(session(&mut connection,&db.config).await,Err(DatabaseError::SchemaIdentity));
        assert_eq!(inspect(&mut connection,&db.config,None,false).await,Err(DatabaseError::SchemaIdentity));
        sqlx::raw_sql("DROP DOMAIN pg_temp.kerb_id; DROP TABLE pg_temp._sqlx_migrations; DROP TABLE pg_temp.ledger_pairs")
            .execute(&mut *connection).await.unwrap();
        session(&mut connection,&db.config).await.unwrap();
        drop(connection);
        let mut checked = pool.acquire().await.unwrap();
        assert_eq!(inspect(&mut checked,&db.config,None,false).await,Ok(true));
        drop(checked);
        pool.close().await; db.remove().await;
    }

    #[tokio::test]
    async fn reused_pool_discards_temporary_relations_and_repins_session_settings() {
        let db = support::TestDatabase::create("poolreuse").await;
        let config = DatabaseConfig { max_connections:1, ..db.config.clone() };
        let pool = connect(&config).await.unwrap();
        let ledger = crate::market::ledger::Ledger::connect(&config).await.unwrap();
        ledger.migrate().await.unwrap(); ledger.close().await;
        let mut connection = pool.acquire().await.unwrap();
        sqlx::raw_sql("CREATE TEMP TABLE ledger_pairs(sentinel TEXT); SET search_path=public,pg_temp; SET synchronous_commit=off")
            .execute(&mut *connection).await.unwrap();
        drop(connection);
        let mut replacement = pool.acquire().await.unwrap();
        let clean: bool = sqlx::query_scalar("SELECT NOT EXISTS(SELECT 1 FROM pg_catalog.pg_class WHERE relnamespace=pg_catalog.pg_my_temp_schema()) AND NOT EXISTS(SELECT 1 FROM pg_catalog.pg_type WHERE typnamespace=pg_catalog.pg_my_temp_schema()) AND EXISTS(SELECT 1 FROM pg_catalog.pg_class c JOIN pg_catalog.pg_namespace n ON n.oid=c.relnamespace WHERE c.oid=pg_catalog.to_regclass('ledger_pairs') AND n.nspname=$1)")
            .bind(&config.schema).fetch_one(&mut *replacement).await.unwrap();
        assert!(clean);
        let settings = sqlx::query_as::<_,(String,String)>("SELECT pg_catalog.current_setting('search_path'),pg_catalog.current_setting('synchronous_commit')")
            .fetch_one(&mut *replacement).await.unwrap();
        assert_eq!(settings,(format!("\"{}\",pg_temp",config.schema),"on".into()));
        drop(replacement);
        let mut checked = pool.acquire().await.unwrap();
        assert_eq!(inspect(&mut checked,&config,None,false).await,Ok(true));
        drop(checked);
        pool.close().await; db.remove().await;
    }

    #[tokio::test]
    async fn application_builtin_name_cannot_redirect_builtin_resolution_and_extra_objects_fail_closed() {
        let db = support::TestDatabase::create("builtin").await;
        let pool = connect(&db.config).await.unwrap();
        let ledger = crate::market::ledger::Ledger::connect(&db.config).await.unwrap();
        ledger.migrate().await.unwrap(); ledger.close().await;
        let mut connection = pool.acquire().await.unwrap();
        sqlx::raw_sql(&format!("CREATE DOMAIN {}.bytea AS TEXT",db.config.schema)).execute(&mut *connection).await.unwrap();
        let kind: String = sqlx::query_scalar("SELECT pg_catalog.pg_typeof(decode('00','hex'))::text").fetch_one(&mut *connection).await.unwrap();
        assert_eq!(kind,"bytea");
        assert_eq!(session(&mut connection,&db.config).await,Err(DatabaseError::SchemaIdentity));
        sqlx::raw_sql(&format!("DROP DOMAIN {}.bytea",db.config.schema)).execute(&mut *connection).await.unwrap();
        session(&mut connection,&db.config).await.unwrap();
        drop(connection);
        pool.close().await; db.remove().await;
    }

    #[tokio::test]
    async fn rls_flags_and_policies_reject_capacity_reads_before_reserving_more_inventory() {
        use crate::store::{ActorStore, InventoryScope, StoreError};
        use ziquid_protocol::NativeAmount;
        let scope = InventoryScope { actor:[1;32], asset:[2;32], deployment:[3;32] };
        let mut ten = [0;32]; ten[31]=10;
        let ten = NativeAmount::from_be_bytes(ten);
        for case in 0..3 {
            let db = support::TestDatabase::create("rlsdrift").await;
            let mut actor = ActorStore::connect(db.config.clone(),scope).await.unwrap();
            actor.migrate().await.unwrap();
            actor.reserve([4;32],[5;32],ten,ten).await.unwrap();
            let prepared = actor.prepare_funding([4;32],[8;32],[9;32]).await.unwrap();
            let mut connection = db.connection().await;
            let retained = sqlx::query_as::<_,(Vec<u8>,Vec<u8>,i16,Option<Vec<u8>>)>(
                &format!("SELECT order_id,amount,state,operation_id FROM \"{}\".reservations ORDER BY order_id",db.config.schema))
                .fetch_all(&mut connection).await.unwrap();
            match case {
                0 => {
                    sqlx::raw_sql(&format!("ALTER TABLE \"{}\".reservations ENABLE ROW LEVEL SECURITY",db.config.schema))
                        .execute(&mut connection).await.unwrap();
                }
                1 => {
                    // A forced owner policy hiding active rows would otherwise
                    // omit their debit from the TOTAL-capacity scan.
                    sqlx::raw_sql(&format!("CREATE POLICY hide_active ON \"{}\".reservations USING(state=0) WITH CHECK(true); ALTER TABLE \"{}\".reservations ENABLE ROW LEVEL SECURITY; ALTER TABLE \"{}\".reservations FORCE ROW LEVEL SECURITY",db.config.schema,db.config.schema,db.config.schema))
                        .execute(&mut connection).await.unwrap();
                }
                _ => {
                    // A dormant policy is drift too: do not accept it merely
                    // because the two RLS relation flags remain false.
                    sqlx::raw_sql(&format!("CREATE POLICY dormant ON \"{}\".reservations USING(state=4)",db.config.schema))
                        .execute(&mut connection).await.unwrap();
                }
            }
            assert_eq!(inspect(&mut connection,&db.config,None,false).await,Err(DatabaseError::SchemaIdentity));
            assert_eq!(session(&mut connection,&db.config).await,Err(DatabaseError::SchemaIdentity));
            // Pool rejection can surface the bounded redacted Connection class;
            // a SQL outage must not be mislabeled as SchemaIdentity.
            assert!(matches!(actor.reserve([6;32],[5;32],ten,ten).await,Err(StoreError::Database(_))));
            sqlx::raw_sql(&format!("ALTER TABLE \"{}\".reservations DISABLE ROW LEVEL SECURITY; ALTER TABLE \"{}\".reservations NO FORCE ROW LEVEL SECURITY; DROP POLICY IF EXISTS hide_active ON \"{}\".reservations; DROP POLICY IF EXISTS dormant ON \"{}\".reservations",db.config.schema,db.config.schema,db.config.schema,db.config.schema))
                .execute(&mut connection).await.unwrap();
            let after = sqlx::query_as::<_,(Vec<u8>,Vec<u8>,i16,Option<Vec<u8>>)>(
                &format!("SELECT order_id,amount,state,operation_id FROM \"{}\".reservations ORDER BY order_id",db.config.schema))
                .fetch_all(&mut connection).await.unwrap();
            assert_eq!(after,retained);
            assert_eq!(inspect(&mut connection,&db.config,None,false).await,Ok(true));
            assert_eq!(actor.reservation([4;32]).await.unwrap().unwrap().amount,ten);
            assert_eq!(actor.funding([8;32]).await.unwrap(),Some(prepared));
            assert_eq!(actor.reservation([6;32]).await.unwrap(),None);
            drop(actor); connection.close().await.unwrap(); db.remove().await;
        }
    }

    #[tokio::test]
    async fn conditional_update_rewrite_is_schema_drift_before_funding_intent_export() {
        use crate::store::{ActorStore, InventoryScope, StoreError};
        use ziquid_protocol::NativeAmount;
        let db = support::TestDatabase::create("ruledrift").await;
        let scope = InventoryScope { actor:[1;32], asset:[2;32], deployment:[3;32] };
        let mut amount = [0;32]; amount[31]=7;
        let amount = NativeAmount::from_be_bytes(amount);
        let mut actor = ActorStore::connect(db.config.clone(),scope).await.unwrap();
        actor.migrate().await.unwrap();
        let reserved = actor.reserve([4;32],[5;32],amount,amount).await.unwrap();
        let mut connection = db.connection().await;
        sqlx::raw_sql(&format!("CREATE RULE suppress_prepare AS ON UPDATE TO \"{}\".reservations WHERE NEW.state=1 DO INSTEAD NOTHING",db.config.schema))
            .execute(&mut connection).await.unwrap();
        assert_eq!(inspect(&mut connection,&db.config,None,false).await,Err(DatabaseError::SchemaIdentity));
        assert_eq!(session(&mut connection,&db.config).await,Err(DatabaseError::SchemaIdentity));
        assert!(matches!(actor.prepare_funding([4;32],[6;32],[7;32]).await,Err(StoreError::Database(_))));
        sqlx::raw_sql(&format!("DROP RULE suppress_prepare ON \"{}\".reservations",db.config.schema))
            .execute(&mut connection).await.unwrap();
        assert_eq!(inspect(&mut connection,&db.config,None,false).await,Ok(true));
        assert_eq!(actor.reservation([4;32]).await.unwrap(),Some(reserved));
        assert_eq!(actor.funding([6;32]).await.unwrap(),None);
        drop(actor); connection.close().await.unwrap(); db.remove().await;
    }
}
