//! EAP load testing (PEAP/MSCHAPv2, the `eapol_test` scenario) by driving
//! external `eapol_test` binaries from wpa_supplicant.
//!
//! Each invocation authenticates exactly once — a full PEAP TLS handshake and
//! inner MS-CHAPv2 exchange — so there is no session resumption and the load
//! on the server matches real supplicants. Workers are per-connection like
//! the pure-RADIUS paths, running auths sequentially.

use std::{fs, path::PathBuf, process::Stdio, time::Duration};

use tokio::process::Command;
use tokio_util::sync::CancellationToken;
use tracing::debug;

use crate::{config::AppConfig, error::AppError};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EapOutcome {
    Success,
    /// Authentication ran to completion but was rejected (EAP-Failure).
    Rejected,
    /// No result within `timeout`.
    Timeout,
    /// Spawn error or eapol_test finished with neither SUCCESS nor FAILURE.
    Error,
    Cancelled,
}

/// Prepared eapol_test invocation for one worker: the generated config file
/// (contains the password, mode 0600) plus the fixed argument list.
pub struct EapolTest {
    conf_path: PathBuf,
    binary: String,
    args: Vec<String>,
}

impl EapolTest {
    pub fn prepare(config: &AppConfig, worker_id: usize) -> Result<Self, AppError> {
        let eap = &config.eap;
        let auth = &config.auth;

        let mut conf = String::from("network={\n");
        conf.push_str("    ssid=\"radperf\"\n");
        conf.push_str("    key_mgmt=WPA-EAP\n");
        conf.push_str("    eap=PEAP\n");
        conf.push_str(&format!(
            "    identity=\"{}\"\n",
            conf_escape(&auth.username)
        ));
        if let Some(anon) = &eap.anonymous_identity {
            conf.push_str(&format!(
                "    anonymous_identity=\"{}\"\n",
                conf_escape(anon)
            ));
        }
        conf.push_str(&format!(
            "    password=\"{}\"\n",
            conf_escape(&auth.password)
        ));
        if let Some(phase1) = &eap.phase1 {
            conf.push_str(&format!("    phase1=\"{}\"\n", conf_escape(phase1)));
        }
        conf.push_str(&format!("    phase2=\"{}\"\n", conf_escape(&eap.phase2)));
        conf.push_str("}\n");

        let conf_path = std::env::temp_dir().join(format!(
            "radperf-eap-{}-{worker_id}.conf",
            std::process::id()
        ));
        fs::write(&conf_path, &conf)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&conf_path, fs::Permissions::from_mode(0o600))?;
        }

        // one distinct client MAC (Calling-Station-Id) per worker
        let mac = format!(
            "02:00:00:{:02X}:{:02X}:{:02X}",
            (worker_id >> 16) & 0xff,
            (worker_id >> 8) & 0xff,
            worker_id & 0xff
        );

        let mut args: Vec<String> = vec![
            "-c".into(),
            conf_path.to_string_lossy().into_owned(),
            "-a".into(),
            config.server.ip().to_string(),
            "-p".into(),
            config.server.port().to_string(),
            "-s".into(),
            config.secret.clone(),
            "-t".into(),
            config.timeout.as_secs().max(1).to_string(),
            "-M".into(),
            mac,
        ];
        for attr in &eap.attrs {
            args.push("-N".into());
            args.push(attr.clone());
        }

        Ok(EapolTest {
            conf_path,
            binary: eap.binary.clone(),
            args,
        })
    }

    /// Runs one full PEAP/MSCHAPv2 authentication.
    pub async fn authenticate(
        &self,
        timeout_dur: Duration,
        cancel: &CancellationToken,
    ) -> EapOutcome {
        let mut cmd = Command::new(&self.binary);
        cmd.args(&self.args)
            .kill_on_drop(true)
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());

        let fut = cmd.output();
        tokio::select! {
            biased;
            _ = cancel.cancelled() => EapOutcome::Cancelled,
            res = tokio::time::timeout(timeout_dur, fut) => match res {
                // kill_on_drop cleans up the child when the future is dropped
                Err(_) => EapOutcome::Timeout,
                Ok(Err(e)) => {
                    debug!("failed to spawn eapol_test: {e}");
                    EapOutcome::Error
                }
                Ok(Ok(output)) => Self::classify(&output.stdout, &output.stderr),
            },
        }
    }

    fn classify(stdout: &[u8], stderr: &[u8]) -> EapOutcome {
        let out = String::from_utf8_lossy(stdout);
        if out.lines().any(|l| l.trim() == "SUCCESS") {
            return EapOutcome::Success;
        }
        if out.lines().any(|l| l.trim() == "FAILURE") {
            return EapOutcome::Rejected;
        }
        debug!(
            "eapol_test finished without SUCCESS/FAILURE\nstdout: {out}\nstderr: {}",
            String::from_utf8_lossy(stderr)
        );
        EapOutcome::Error
    }
}

impl Drop for EapolTest {
    fn drop(&mut self) {
        let _ = fs::remove_file(&self.conf_path);
    }
}

fn conf_escape(value: &str) -> String {
    value.replace('\\', "\\\\").replace('"', "\\\"")
}

/// Verifies that the configured eapol_test binary can be executed (any exit
/// code is fine — running it without arguments prints usage).
pub fn check_binary(binary: &str) -> Result<(), AppError> {
    std::process::Command::new(binary)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .map(|_| ())
        .map_err(|e| {
            AppError::RequestError(format!("cannot run eapol_test binary '{binary}': {e}"))
        })
}
