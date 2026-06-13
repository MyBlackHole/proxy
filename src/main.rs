use clap::{Parser, Subcommand};
use std::path::Path;

#[derive(Parser)]
#[command(
    name = "proxy-collector",
    about = "代理采集工具 - 多源爬取、验证、转换和推送代理节点"
)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// 采集模式：多源爬取 → 解析 → 验证 → 持久化到磁盘
    Crawl {
        #[arg(short = 's', long = "config", help = "Path to configuration file")]
        config: Option<String>,

        #[arg(
            short = 'n',
            long = "concurrency",
            default_value_t = 64,
            help = "Concurrency level for health checks"
        )]
        concurrency: usize,
    },

    /// 转换模式：从持久化数据读取 → 去重 → 生成 Clash 配置 → 推送存储
    Convert {
        #[arg(short = 's', long = "config", help = "Path to configuration file")]
        config: Option<String>,
    },

    /// 验证 Clash 配置文件
    Validate {
        #[arg(help = "Path to Clash config file to validate")]
        path: String,

        #[arg(
            long = "validate-bin",
            help = "Path to mihomo/clash-meta binary for config validation"
        )]
        validate_bin: Option<String>,
    },
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    env_logger::Builder::from_env(env_logger::Env::default())
        .filter_module("reqwest", log::LevelFilter::Warn)
        .init();

    let cli = Cli::parse();

    match cli.command {
        Commands::Crawl { config, concurrency } => {
            let config_path = config.unwrap_or_else(|| {
                eprintln!("Error: --config <CONFIG> is required");
                std::process::exit(1);
            });
            log::info!("Crawl mode — config: {}, concurrency: {}", config_path, concurrency);
            proxy_collector::workflow::run_crawl(&config_path, concurrency).await?;
            println!("Crawl completed successfully");
        }
        Commands::Convert { config } => {
            let config_path = config.unwrap_or_else(|| {
                eprintln!("Error: --config <CONFIG> is required");
                std::process::exit(1);
            });
            log::info!("Convert mode — config: {}", config_path);
            proxy_collector::workflow::run_convert(&config_path).await?;
            println!("Convert completed successfully");
        }
        Commands::Validate { path, validate_bin } => {
            return validate_mode(&path, validate_bin.as_deref().map(Path::new));
        }
    }

    Ok(())
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
