use clap::Parser;
use std::path::Path;

#[derive(Parser)]
#[command(
    name = "proxy-collector",
    about = "代理采集工具 - 多源爬取、验证、转换和推送代理节点"
)]
struct Args {
    #[arg(short = 's', long = "config", help = "Path to configuration file")]
    config: Option<String>,

    #[arg(
        long = "check",
        help = "Run health check only without fetching new subscriptions"
    )]
    check: bool,

    #[arg(
        short = 'n',
        long = "concurrency",
        default_value_t = 64,
        help = "Concurrency level for health checks"
    )]
    concurrency: usize,

    #[arg(
        long = "validate",
        help = "Validate a Clash config file using mihomo -t"
    )]
    validate: Option<String>,

    #[arg(
        long = "validate-bin",
        help = "Path to mihomo/clash-meta binary for config validation"
    )]
    validate_bin: Option<String>,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    env_logger::Builder::from_env(env_logger::Env::default())
        // Reqwest's internal connection-level debug logs are extremely
        // repetitive when many URLs share the same host — suppress them.
        .filter_module("reqwest", log::LevelFilter::Warn)
        .init();

    let args = Args::parse();

    // Validate mode
    if let Some(path) = args.validate {
        return validate_mode(&path, args.validate_bin.as_deref().map(Path::new));
    }

    let config = args.config.unwrap_or_else(|| {
        eprintln!("Error: --config <CONFIG> is required");
        std::process::exit(1);
    });

    log::info!("Starting proxy-collector");
    log::info!("Config: {}", config);
    log::info!("Concurrency: {}", args.concurrency);

    let result = if args.check {
        proxy_collector::workflow::check_alive_only(&config).await
    } else {
        proxy_collector::workflow::run_workflow(&config).await
    };

    match result {
        Ok(_) => {
            println!("Workflow completed successfully");
            log::info!("Workflow completed successfully");
            Ok(())
        }
        Err(e) => {
            log::error!("Workflow failed: {}", e);
            eprintln!("Error: {}", e);
            Err(e.into())
        }
    }
}

fn validate_mode(path: &str, binary: Option<&Path>) -> anyhow::Result<()> {
    use proxy_collector::validate::{validate_clash_config, ValidateResult};

    let config_path = Path::new(path);
    let result = match validate_clash_config(config_path, binary) {
        Ok(r) => r,
        Err(e) => e,
    };

    match result {
        ValidateResult::Valid { version } => {
            println!("✅ Config valid: {}", path);
            println!("   Checked by: {}", version);
            Ok(())
        }
        ValidateResult::Invalid { errors, temp_dir } => {
            eprintln!("❌ Config invalid: {}", path);
            for err in &errors {
                eprintln!("   ❌ {}", err);
            }
            if !temp_dir.as_os_str().is_empty() {
                eprintln!("   Temp dir preserved: {}", temp_dir.display());
            }
            anyhow::bail!("Config validation failed with {} error(s)", errors.len());
        }
        ValidateResult::BinaryNotFound { searched } => {
            eprintln!("❌ No clash-compatible binary found.");
            eprintln!("   Searched: {}", searched.join(", "));
            eprintln!("   Install mihomo: https://github.com/MetaCubeX/mihomo/releases");
            anyhow::bail!("mihomo not found");
        }
        ValidateResult::Error { message } => {
            eprintln!("❌ Validation error: {}", message);
            anyhow::bail!("{}", message);
        }
    }
}
