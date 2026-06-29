use std::net::TcpListener;
use std::sync::Arc;

use anyhow::{Context, Result};
use clap::{Parser, ValueEnum};
use decant_backend::MemoryBackend;
use decant_daemon::{serve, Diag};

#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
enum BackendKind {
    Mock,
    Memflow,
}

#[derive(Debug, Parser)]
#[command(name = "decant-daemon", about = "Decant daemon, serves guest memory over TCP")]
struct Args {
    #[arg(long, default_value = "127.0.0.1:7878")]
    bind: String,

    #[arg(long, value_enum, default_value_t = BackendKind::Mock)]
    backend: BackendKind,

    #[arg(long, env = "DECANT_CONNECTOR", default_value = "qemu")]
    connector: String,
}

fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .init();

    let args = Args::parse();
    let (backend, connector) = build_backend(args.backend, &args.connector)?;

    let listener = TcpListener::bind(&args.bind)
        .with_context(|| format!("binding {}", args.bind))?;
    let local = listener.local_addr().context("resolving bound address")?;

    println!("decant-daemon listening on {local} (backend: {connector})");
    tracing::info!(%local, %connector, "decant-daemon started");

    let diag = Arc::new(Diag::new(connector));
    serve(listener, backend, diag).context("serving")?;
    Ok(())
}

fn build_backend(kind: BackendKind, connector: &str) -> Result<(Arc<dyn MemoryBackend>, String)> {
    match kind {
        BackendKind::Mock => {
            Ok((Arc::new(decant_backend::fixtures::demo_backend()), "mock".to_string()))
        }
        BackendKind::Memflow => build_memflow_backend(connector),
    }
}

#[cfg(feature = "memflow")]
fn build_memflow_backend(connector: &str) -> Result<(Arc<dyn MemoryBackend>, String)> {
    let backend = decant_memflow::MemflowBackend::connect(connector)
        .with_context(|| format!("connecting memflow backend (connector: {connector})"))?;
    Ok((Arc::new(backend), format!("memflow:{connector}")))
}

#[cfg(not(feature = "memflow"))]
fn build_memflow_backend(_connector: &str) -> Result<(Arc<dyn MemoryBackend>, String)> {
    anyhow::bail!(
        "this decant-daemon build has no memflow support. Rebuild on the VM host with:\n    \
         cargo build --release -p decant-daemon --features memflow\n\
         (the memflow QEMU/KVM connector plugin must also be installed, see docs/DECISIONS.md ADR-0005)."
    )
}
