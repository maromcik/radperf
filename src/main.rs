use std::time::Instant;

use clap::Parser;
use tokio_util::sync::CancellationToken;
use tracing::{error, info};
use tracing_subscriber::EnvFilter;

use crate::config::AppConfig;
use crate::error::AppError;
use crate::perf::{PerfTest, RadiusPacket};

mod acct;
mod config;
mod eap;
mod error;
mod mschapv2;
mod perf;
mod utils;

#[derive(Parser)]
#[clap(author, version, about, long_about = None)]
struct Cli {
    #[clap(short, long, value_name = "CONFIG_FILE", default_value = "radperf")]
    config: String,
}

#[tokio::main]
async fn main() -> Result<(), AppError> {
    let cli = Cli::parse();
    let config = AppConfig::parse_config(cli.config.as_ref())?;

    let filter = EnvFilter::try_new(&config.log_level).unwrap_or_else(|_| EnvFilter::new("info"));
    let timer = tracing_subscriber::fmt::time::LocalTime::rfc_3339();
    tracing_subscriber::fmt()
        .with_timer(timer)
        .with_target(true)
        .with_env_filter(filter)
        .init();

    // validate that the config can actually produce requests before starting
    // the test (workers rebuild fresh packets / spawn processes per request)
    if config.auth.method == config::AuthMethod::PeapMschapv2 {
        eap::check_binary(&config.eap.binary)?;
    } else if config.packet_type == config::PacketCode::AccountingRequest {
        acct::AcctSession::new(0, config.accounting.framed_ip)
            .build_packet(&config, config::AcctStatusKind::Start)?;
    } else {
        RadiusPacket::build(&config)?;
    }
    let test = PerfTest::new(config);
    let cancel = CancellationToken::new();
    let started_at = Instant::now();

    let run = test.run(cancel.clone());
    tokio::pin!(run);
    tokio::select! {
        res = &mut run => {
            if let Err(e) = res {
                error!("perf test failed: {e}");
            }
        }
        _ = tokio::signal::ctrl_c() => {
            info!("ctrl-c received, stopping workers...");
            cancel.cancel();
            if let Err(e) = run.await {
                error!("perf test failed: {e}");
            }
        }
    }

    test.print_summary(started_at.elapsed());
    Ok(())
}
