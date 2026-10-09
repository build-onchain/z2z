use super::{
    Error, Result,
    config::{self, ReplicaConfig},
};
use ed25519_dalek::SigningKey;
use crate::market::ledger::{
    JournalAcknowledgement, JournalDecision, MAX_JOURNAL_BYTES, PairPolicy, RecoveryChallenge,
    Replica, RetainedHead,
};
use ziquid_protocol::market::{Id, ObservationEnvironment};
use std::{path::Path, process::Stdio, time::Duration};
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt},
    process::{Child, ChildStdin, ChildStdout, Command},
};

pub const FIXTURE_HEADER: &[u8; 8] = b"KERBFX01";
const READY: &[u8; 8] = b"KERBRD01";
const FAILURE: &[u8; 8] = b"KERBER01";
// ponytail: fixed local exchange/exit ceilings; add owner-configured budgets only
// when actual operator workloads need longer than30s requests or5s shutdown.
pub(crate) const EXCHANGE_TIMEOUT: Duration = Duration::from_secs(30);
pub(crate) const SHUTDOWN_TIMEOUT: Duration = Duration::from_secs(5);

pub async fn read_fixture_keys<const N: usize>(
    input: &mut (impl AsyncRead + Unpin),
) -> Result<[SigningKey; N]> {
    let mut header = [0; 8];
    input
        .read_exact(&mut header)
        .await
        .map_err(|_| Error::KeyBootstrap)?;
    if &header != FIXTURE_HEADER {
        return Err(Error::KeyBootstrap);
    }
    let mut keys = Vec::with_capacity(N);
    for _ in 0..N {
        let mut seed = [0; 32];
        input
            .read_exact(&mut seed)
            .await
            .map_err(|_| Error::KeyBootstrap)?;
        keys.push(SigningKey::from_bytes(&seed));
        seed.fill(0);
    }
    keys.try_into().map_err(|_| Error::KeyBootstrap)
}

pub async fn write_frame(output: &mut (impl AsyncWrite + Unpin), bytes: &[u8]) -> Result<()> {
    if bytes.is_empty() || bytes.len() > MAX_JOURNAL_BYTES {
        return Err(Error::Frame);
    }
    output
        .write_all(&(bytes.len() as u32).to_le_bytes())
        .await
        .map_err(|_| Error::Process)?;
    output.write_all(bytes).await.map_err(|_| Error::Process)?;
    output.flush().await.map_err(|_| Error::Process)
}

pub async fn read_frame(input: &mut (impl AsyncRead + Unpin)) -> Result<Option<Vec<u8>>> {
    let mut size = [0; 4];
    match input.read(&mut size[..1]).await {
        Ok(0) => return Ok(None),
        Ok(_) => {}
        Err(_) => return Err(Error::Process),
    }
    input
        .read_exact(&mut size[1..])
        .await
        .map_err(|_| Error::Frame)?;
    let size = u32::from_le_bytes(size) as usize;
    if size == 0 || size > MAX_JOURNAL_BYTES {
        return Err(Error::Frame);
    }
    let mut bytes = vec![0; size];
    input
        .read_exact(&mut bytes)
        .await
        .map_err(|_| Error::Frame)?;
    Ok(Some(bytes))
}

pub async fn replica(config: ReplicaConfig, fixture_key_stdin: bool) -> Result<()> {
    config::version(config.schema_version)?;
    let policy = config::policy(&config.policy)?;
    if !fixture_key_stdin
        || policy.environment != ObservationEnvironment::LocalFixture
        || !policy.roster.contains(&config.expected_signer)
    {
        return Err(Error::Configuration);
    }
    let mut input = tokio::io::stdin();
    let mut output = tokio::io::stdout();
    let [signer] = tokio::time::timeout(EXCHANGE_TIMEOUT, read_fixture_keys::<1>(&mut input))
        .await
        .map_err(|_| Error::ProcessTimeout)??;
    if signer.verifying_key().to_bytes() != config.expected_signer {
        return Err(Error::KeyBootstrap);
    }
    let replica = Replica::connect(&config.database.config()?).await?;
    let result = async {
        replica.migrate().await?;
        replica.enroll_pair(&policy).await?;
        let mut hello = Vec::with_capacity(40);
        hello.extend_from_slice(READY);
        hello.extend_from_slice(&config.expected_signer);
        write_frame(&mut output, &hello).await?;
        while let Some(frame) = read_frame(&mut input).await? {
            if frame[0] == 3 {
                if frame.len() != 1 {
                    return Err(Error::Frame);
                }
                write_frame(&mut output, b"KERBSTOP").await?;
                break;
            }
            let response = match frame[0] {
                1 => match JournalDecision::decode(&frame[1..]) {
                    Ok(decision) => replica
                        .acknowledge(&decision, &signer)
                        .await
                        .and_then(|ack| ack.canonical_bytes()),
                    Err(error) => Err(error),
                },
                2 => match RecoveryChallenge::decode(&frame[1..]) {
                    Ok(challenge) => replica
                        .retained_head(&challenge, &signer)
                        .await
                        .and_then(|head| head.canonical_bytes().map(Vec::from)),
                    Err(error) => Err(error),
                },
                _ => return Err(Error::Frame),
            };
            match response {
                Ok(bytes) => write_frame(&mut output, &bytes).await?,
                Err(error) => {
                    let mut bytes = FAILURE.to_vec();
                    bytes.extend_from_slice(error.to_string().as_bytes());
                    write_frame(&mut output, &bytes).await?;
                }
            }
        }
        Ok(())
    }
    .await;
    replica.close().await;
    result
}

pub struct ReplicaProcess {
    child: Child,
    input: ChildStdin,
    output: ChildStdout,
    signer: Id,
    pid: u32,
}
fn replica_command(executable: &Path, path: &Path, database: &config::Database) -> Result<Command> {
    database.config()?;
    let mut command = Command::new(executable);
    command
        .args(["market", "replica", "--config"])
        .arg(path)
        .arg("--local-fixture-key-stdin")
        .env_clear();
    if let Some(uri) = std::env::var_os(&database.uri_env) {
        command.env(&database.uri_env, uri);
    }
    Ok(command)
}

impl ReplicaProcess {
    pub async fn launch(
        executable: &Path,
        path: &Path,
        signer: &SigningKey,
        policy: &PairPolicy,
    ) -> Result<Self> {
        let cfg: ReplicaConfig = config::read(path)?;
        config::version(cfg.schema_version)?;
        if config::policy(&cfg.policy)? != *policy
            || cfg.expected_signer != signer.verifying_key().to_bytes()
        {
            return Err(Error::Configuration);
        }
        let mut child = replica_command(executable, path, &cfg.database)?
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::inherit())
            .kill_on_drop(true)
            .spawn()
            .map_err(|_| Error::Process)?;
        let input = child.stdin.take().ok_or(Error::Process)?;
        let output = child.stdout.take().ok_or(Error::Process)?;
        let pid = child.id().ok_or(Error::Process)?;
        let mut process = Self {
            child,
            input,
            output,
            signer: cfg.expected_signer,
            pid,
        };
        let result = tokio::time::timeout(EXCHANGE_TIMEOUT, async {
            process
                .input
                .write_all(FIXTURE_HEADER)
                .await
                .map_err(|_| Error::Process)?;
            process
                .input
                .write_all(&signer.to_bytes())
                .await
                .map_err(|_| Error::Process)?;
            process.input.flush().await.map_err(|_| Error::Process)?;
            let hello = read_frame(&mut process.output)
                .await?
                .ok_or(Error::Process)?;
            if hello.len() != 40 || &hello[..8] != READY || hello[8..] != process.signer {
                return Err(Error::Process);
            }
            Ok(())
        })
        .await
        .map_err(|_| Error::ProcessTimeout)
        .and_then(|result| result);
        if let Err(error) = result {
            process.kill().await?;
            return Err(error);
        }
        Ok(process)
    }
    async fn request(&mut self, tag: u8, bytes: &[u8]) -> Result<Vec<u8>> {
        if bytes.len() >= MAX_JOURNAL_BYTES {
            return Err(Error::Frame);
        }
        let mut frame = Vec::with_capacity(bytes.len() + 1);
        frame.push(tag);
        frame.extend_from_slice(bytes);
        let result = tokio::time::timeout(EXCHANGE_TIMEOUT, async {
            write_frame(&mut self.input, &frame).await?;
            let response = read_frame(&mut self.output).await?.ok_or(Error::Process)?;
            if response.starts_with(FAILURE) {
                return Err(Error::Process);
            }
            Ok(response)
        })
        .await
        .map_err(|_| Error::ProcessTimeout)
        .and_then(|result| result);
        if result.is_err() {
            self.kill().await?;
        }
        result
    }
    pub async fn acknowledge(
        &mut self,
        decision: &JournalDecision,
    ) -> Result<JournalAcknowledgement> {
        let response = self.request(1, &decision.canonical_bytes()?).await?;
        let ack = JournalAcknowledgement::decode(&response)?;
        if ack.signer != self.signer || ack.decision != *decision {
            return Err(Error::Process);
        }
        Ok(ack)
    }
    pub async fn retained(&mut self, challenge: &RecoveryChallenge) -> Result<RetainedHead> {
        let response = self.request(2, &challenge.canonical_bytes()).await?;
        let head = RetainedHead::decode(&response)?;
        if head.signer != self.signer
            || head.pair != challenge.pair
            || head.challenge != challenge.nonce
        {
            return Err(Error::Process);
        }
        Ok(head)
    }
    pub fn id(&self) -> u32 {
        self.pid
    }
    pub async fn shutdown(&mut self) -> Result<()> {
        if let Some(status) = self.child.try_wait().map_err(|_| Error::Process)? {
            return if status.success() {
                Ok(())
            } else {
                Err(Error::Process)
            };
        }
        let result = tokio::time::timeout(SHUTDOWN_TIMEOUT, async {
            write_frame(&mut self.input, &[3]).await?;
            if read_frame(&mut self.output).await?.as_deref() != Some(b"KERBSTOP".as_slice()) {
                return Err(Error::Process);
            }
            let status = self.child.wait().await.map_err(|_| Error::Process)?;
            if status.success() {
                Ok(())
            } else {
                Err(Error::Process)
            }
        })
        .await
        .map_err(|_| Error::ProcessTimeout)
        .and_then(|result| result);
        if result.is_err() {
            self.kill().await?;
        }
        result
    }
    pub async fn kill(&mut self) -> Result<()> {
        if self.child.try_wait().map_err(|_| Error::Process)?.is_none() {
            self.child.kill().await.map_err(|_| Error::Process)?;
        }
        self.child.wait().await.map_err(|_| Error::Process)?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn self_spawn_prefixes_market_and_preserves_one_non_utf8_config_argument() {
        use std::{ffi::OsString, os::unix::ffi::OsStringExt, path::PathBuf};
        let path = PathBuf::from(OsString::from_vec(b"/tmp/market config-\xff.json".to_vec()));
        let database = config::Database {
            uri_env: "Z2Z_PROCESS_FIXTURE_URI_NOT_CONFIGURED".into(),
            schema: "z2z_fixture_process".into(),
            max_connections: 1,
        };
        let command = replica_command(Path::new("/app/ziquid"), &path, &database).unwrap();
        let arguments = command.as_std().get_args().collect::<Vec<_>>();
        assert_eq!(arguments, [
            std::ffi::OsStr::new("market"),
            std::ffi::OsStr::new("replica"),
            std::ffi::OsStr::new("--config"),
            path.as_os_str(),
            std::ffi::OsStr::new("--local-fixture-key-stdin"),
        ]);
        assert_eq!(command.as_std().get_program(), "/app/ziquid");
    }
}
