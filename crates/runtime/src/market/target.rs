use super::{
    Error, Result,
    native::unhex,
    process::{EXCHANGE_TIMEOUT, FIXTURE_HEADER, SHUTDOWN_TIMEOUT},
};
use ed25519_dalek::SigningKey;
use ziquid_protocol::market::{ACKNOWLEDGEMENT_LEN, Acknowledgement, Decision, Domain, Id};
use std::{collections::BTreeMap, path::Path, process::Stdio};
use tokio::{
    io::{AsyncBufReadExt, AsyncWriteExt, BufReader},
    process::{Child, ChildStdin, ChildStdout, Command},
};

const MAX_SECTION_BYTES: usize = 64 * 1024;
const MAX_LINE_BYTES: usize = 8192;

pub struct TargetProcess {
    child: Child,
    input: ChildStdin,
    output: BufReader<ChildStdout>,
}
impl TargetProcess {
    pub async fn launch(executable: &Path, elf: &Path, keys: &[SigningKey; 3]) -> Result<Self> {
        if !executable.is_absolute() || !elf.is_absolute() {
            return Err(Error::Configuration);
        }
        let mut child = Command::new(executable)
            .env_clear()
            .env("Z2Z_SBF_ELF", elf)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::inherit())
            .kill_on_drop(true)
            .spawn()
            .map_err(|_| Error::Process)?;
        let input = child.stdin.take().ok_or(Error::Process)?;
        let output = BufReader::new(child.stdout.take().ok_or(Error::Process)?);
        let mut process = Self {
            child,
            input,
            output,
        };
        let result = tokio::time::timeout(EXCHANGE_TIMEOUT, async {
            process
                .input
                .write_all(FIXTURE_HEADER)
                .await
                .map_err(|_| Error::Process)?;
            for key in keys {
                process
                    .input
                    .write_all(&key.to_bytes())
                    .await
                    .map_err(|_| Error::Process)?;
            }
            process.input.flush().await.map_err(|_| Error::Process)
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
    pub async fn section(&mut self, end: &str) -> Result<Section> {
        let result = tokio::time::timeout(EXCHANGE_TIMEOUT, self.read_section(end))
            .await
            .map_err(|_| Error::ProcessTimeout)
            .and_then(|result| result);
        if result.is_err() {
            self.kill().await?;
        }
        result
    }
    async fn read_section(&mut self, end: &str) -> Result<Section> {
        let mut section = Section {
            fields: BTreeMap::new(),
        };
        let mut size = 0;
        loop {
            let mut line = Vec::new();
            loop {
                let available = self.output.fill_buf().await.map_err(|_| Error::Process)?;
                if available.is_empty() {
                    return Err(Error::TargetReceipt);
                }
                let count = available
                    .iter()
                    .position(|byte| *byte == b'\n')
                    .map(|i| i + 1)
                    .unwrap_or(available.len());
                if line.len() + count > MAX_LINE_BYTES
                    || size + line.len() + count > MAX_SECTION_BYTES
                {
                    return Err(Error::TargetReceipt);
                }
                let finished = available[count - 1] == b'\n';
                line.extend_from_slice(&available[..count]);
                self.output.consume(count);
                if finished {
                    break;
                }
            }
            size += line.len();
            let line =
                std::str::from_utf8(&line[..line.len() - 1]).map_err(|_| Error::TargetReceipt)?;
            let (key, value) = line.split_once('=').ok_or(Error::TargetReceipt)?;
            if key == "end" {
                if value != end {
                    return Err(Error::TargetReceipt);
                }
                return Ok(section);
            }
            if key.is_empty()
                || section
                    .fields
                    .insert(key.to_owned(), value.to_owned())
                    .is_some()
            {
                return Err(Error::TargetReceipt);
            }
        }
    }
    pub async fn approve(
        &mut self,
        decision: &Decision,
        acknowledgements: &[Acknowledgement],
        roster: &[Id; 3],
    ) -> Result<()> {
        ziquid_protocol::market::verify_unanimous(decision, acknowledgements, roster)
            .map_err(|_| Error::TargetReceipt)?;
        let result = tokio::time::timeout(EXCHANGE_TIMEOUT, async {
            for ack in acknowledgements {
                let mut bytes = [0; ACKNOWLEDGEMENT_LEN];
                ack.encode_into(&mut bytes)
                    .map_err(|_| Error::TargetReceipt)?;
                self.input
                    .write_all(&bytes)
                    .await
                    .map_err(|_| Error::Process)?;
            }
            self.input.flush().await.map_err(|_| Error::Process)
        })
        .await
        .map_err(|_| Error::ProcessTimeout)
        .and_then(|result| result);
        if result.is_err() {
            self.kill().await?;
        }
        result
    }
    pub async fn finish(&mut self) -> Result<()> {
        let result = tokio::time::timeout(SHUTDOWN_TIMEOUT, self.child.wait())
            .await
            .map_err(|_| Error::ProcessTimeout)
            .and_then(|status| status.map_err(|_| Error::Process))
            .and_then(|status| {
                if status.success() {
                    Ok(())
                } else {
                    Err(Error::Process)
                }
            });
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

pub struct Section {
    fields: BTreeMap<String, String>,
}
impl Section {
    pub fn text(&self, key: &str) -> Result<&str> {
        self.fields
            .get(key)
            .map(String::as_str)
            .ok_or(Error::TargetReceipt)
    }
    pub fn number(&self, key: &str) -> Result<u64> {
        let value = self.text(key)?;
        if value.is_empty()
            || (value.len() > 1 && value.starts_with('0'))
            || !value.bytes().all(|b| b.is_ascii_digit())
        {
            return Err(Error::TargetReceipt);
        }
        value.parse().map_err(|_| Error::TargetReceipt)
    }
    pub fn bytes(&self, key: &str) -> Result<Vec<u8>> {
        unhex(self.text(key)?)
    }
    pub fn array<const N: usize>(&self, key: &str) -> Result<[u8; N]> {
        self.bytes(key)?
            .try_into()
            .map_err(|_| Error::TargetReceipt)
    }
    pub fn id(&self, key: &str) -> Result<Id> {
        self.array(key)
    }
    pub fn domain(&self, key: &str) -> Result<Domain> {
        Domain::decode(&self.bytes(key)?).map_err(|_| Error::TargetReceipt)
    }
    pub fn decision(&self, key: &str) -> Result<Decision> {
        Decision::decode(&self.bytes(key)?).map_err(|_| Error::TargetReceipt)
    }
    pub fn ids(&self, key: &str) -> Result<Vec<Id>> {
        let bytes = self.bytes(key)?;
        if !bytes.len().is_multiple_of(32) || bytes.len() > 32 * 32 {
            return Err(Error::TargetReceipt);
        }
        Ok(bytes.as_chunks::<32>().0.to_vec())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{sync::mpsc, thread, time::Duration};

    #[tokio::test]
    async fn stopped_real_target_finish_errors_and_reaps_without_waiting_for_watchdog() {
        let binary = std::path::PathBuf::from(
            std::env::var_os("Z2Z_TEST_SOLANA_BIN")
                .expect("actual compiled target process required"),
        );
        let elf = std::path::PathBuf::from(
            std::env::var_os("Z2Z_SBF_ELF").expect("actual compiled Kerb ELF required"),
        );
        let keys = [
            crate::market::facts::key().unwrap(),
            crate::market::facts::key().unwrap(),
            crate::market::facts::key().unwrap(),
        ];
        let mut target = TargetProcess::launch(&binary, &elf, &keys).await.unwrap();
        let header = target.section("header").await.unwrap();
        assert_eq!(header.number("escrow_balance").unwrap(), 7);
        assert_eq!(
            target.section("plan").await.unwrap().text("step").unwrap(),
            "commit"
        );
        let pid = target.child.id().unwrap();
        assert!(
            std::process::Command::new("/bin/kill")
                .arg("-STOP")
                .arg(pid.to_string())
                .status()
                .unwrap()
                .success()
        );
        let (cancel, receive) = mpsc::sync_channel(1);
        let watchdog = thread::spawn(
            move || match receive.recv_timeout(Duration::from_secs(10)) {
                Err(mpsc::RecvTimeoutError::Timeout) => {
                    assert!(
                        std::process::Command::new("/bin/kill")
                            .arg("-KILL")
                            .arg(pid.to_string())
                            .status()
                            .unwrap()
                            .success()
                    );
                    false
                }
                _ => true,
            },
        );
        let result = target.finish().await;
        let _ = cancel.send(());
        let bounded = watchdog.join().unwrap();
        assert!(!std::path::Path::new(&format!("/proc/{pid}")).exists());
        assert!(
            bounded,
            "actual silent target finish waited forever instead of deadline kill/reap"
        );
        assert!(matches!(result, Err(Error::ProcessTimeout)));
    }
}
