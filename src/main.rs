use clap::{Parser, Subcommand};
use gxtools::commands::{check, compliance, net, pentest};
use std::process;

#[derive(Parser, Debug)]
#[command(name = "gxtools")]
#[command(version, about = "GX安全工具箱 - 网络测试、渗透测试、等保核查工具集", long_about = None)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand, Debug)]
enum Commands {
    /// 网络测试模块
    Net {
        #[command(subcommand)]
        subcommand: NetCommands,
    },
    /// 等保核查模块
    Check {
        #[command(subcommand)]
        subcommand: CheckCommands,
    },
    /// 合规分析与报告
    Compliance {
        #[command(subcommand)]
        subcommand: ComplianceCommands,
    },
    /// 渗透测试模块
    Pentest {
        #[command(subcommand)]
        subcommand: PentestCommands,
    },
}

#[derive(Subcommand, Debug)]
enum PentestCommands {
    /// 端口扫描工具
    Scan(pentest::portscan::PortScan),
    /// POC测试模块
    Poctest(pentest::poctest::PocTest),
    /// URL路径探测
    Urlscan(pentest::urlscan::UrlScan),
    /// URL截图工具
    Screenshot(pentest::screenshot::ScreenshotArgs),
    /// 弱口令扫描工具
    Weakpass(pentest::weakpass::WeakPassArgs),
}

#[derive(Subcommand, Debug)]
enum NetCommands {
    /// Ping主机存活扫描
    Ping(net::ping::PingArgs),
    /// 路由追踪（纯 Rust 实现，不调用系统 traceroute）
    Trace(net::trace::TraceArgs),
}

#[derive(Subcommand, Debug)]
enum CheckCommands {
    /// Linux系统基线采集（通过SSH）
    Linux(check::ssh::SshArgs),
    /// MySQL数据库基线采集
    Mysql(check::mysql::MysqlArgs),
    /// Oracle数据库基线采集
    Oracle(check::oracle::OracleArgs),
    /// Windows系统基线采集
    Windows(check::windows::WindowsArgs),
    /// Redis数据库基线采集
    Redis(check::redis::RedisArgs),
}

#[derive(Subcommand, Debug)]
enum ComplianceCommands {
    /// 读取采集结果，生成差距分析报告
    Analyze(compliance::analyze::AnalyzeArgs),
}

#[tokio::main]
async fn main() {
    let cli = Cli::parse();

    let result = match cli.command {
        Commands::Net { subcommand } => handle_net_command(subcommand).await,
        Commands::Check { subcommand } => handle_check_command(subcommand).await,
        Commands::Compliance { subcommand } => handle_compliance_command(subcommand).await,
        Commands::Pentest { subcommand } => handle_pentest_command(subcommand).await,
    };

    if let Err(e) = result {
        eprintln!("❌ 执行失败: {}", e);
        process::exit(1);
    }
}

async fn handle_net_command(
    cmd: NetCommands,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    match cmd {
        NetCommands::Ping(args) => net::ping::run(&args).await,
        NetCommands::Trace(args) => tokio::task::block_in_place(|| net::trace::run(&args)),
    }
}

async fn handle_check_command(
    cmd: CheckCommands,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    match cmd {
        CheckCommands::Linux(args) => check::ssh::run(&args).await,
        CheckCommands::Mysql(args) => check::mysql::run(&args).await,
        CheckCommands::Oracle(args) => {
            check::oracle::try_set_oracle_client_path()?;
            check::oracle::run(&args).await
        }
        CheckCommands::Windows(args) => check::windows::run(&args).await,
        CheckCommands::Redis(args) => check::redis::run(&args).await,
    }
}

async fn handle_pentest_command(
    cmd: PentestCommands,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    match cmd {
        PentestCommands::Scan(args) => pentest::portscan::run(&args).await,
        PentestCommands::Poctest(args) => pentest::poctest::run(&args).await,
        PentestCommands::Urlscan(args) => pentest::urlscan::run(&args).await,
        PentestCommands::Screenshot(args) => pentest::screenshot::run(&args).await,
        PentestCommands::Weakpass(args) => pentest::weakpass::run(&args).await,
    }
}

async fn handle_compliance_command(
    cmd: ComplianceCommands,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    match cmd {
        ComplianceCommands::Analyze(args) => compliance::analyze::run(&args).await,
    }
}
