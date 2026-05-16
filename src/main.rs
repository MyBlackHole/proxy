use clap::Parser;

#[derive(Parser)]
#[command(
    name = "proxy-collector",
    about = "代理采集工具 - 多源爬取、验证、转换和推送代理节点"
)]
struct Args {
    #[arg(short = 's', long = "config", help = "Path to configuration file")]
    config: String,

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
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    env_logger::init();

    let args = Args::parse();

    log::info!("Starting proxy-collector");
    log::info!("Config: {}", args.config);
    log::info!("Concurrency: {}", args.concurrency);

    let result = if args.check {
        proxy_collector::workflow::check_alive_only(&args.config).await
    } else {
        proxy_collector::workflow::run_workflow(&args.config).await
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
