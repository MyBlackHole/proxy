use clap::{Parser, Subcommand};

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
    }

    Ok(())
}
