use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt, EnvFilter, Registry};
use std::fs::OpenOptions;
use std::io;
use tracing_subscriber::fmt;

pub fn init_logging(log_level: &str) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let log_file = OpenOptions::new()
        .create(true)
        .write(true)
        .append(true)
        .open("lark_messager.log")?;

    let env_filter = EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| EnvFilter::new(log_level));

    let stdout_layer = fmt::layer()
        .with_target(true)
        .with_thread_ids(true)
        .with_level(true)
        .with_ansi(true)
        .with_writer(io::stdout);

    let file_layer = fmt::layer()
        .with_target(true)
        .with_thread_ids(true)
        .with_level(true)
        .with_ansi(false)
        .with_writer(log_file);

    Registry::default()
        .with(env_filter)
        .with(stdout_layer)
        .with(file_layer)
        .init();

    Ok(())
}