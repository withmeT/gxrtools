use axum::{
    routing::{get, post},
    extract::{connect_info::ConnectInfo, State},
    response::{IntoResponse, Response},
    Json, Router,
    http::{StatusCode, header, HeaderMap, HeaderValue},
};
use serde_json::Value;
use std::{net::SocketAddr, sync::Arc};
use encoding_rs::UTF_16LE;
use clap::Args;
use crate::utils::{OutputArgs, ensure_module_output_dir, sanitize_json};
use hyper::{Server, server::conn::AddrIncoming};
use tokio::fs;
use std::fs as stdfs;
use local_ip_address::local_ip;
use std::net::IpAddr;
use std::str::FromStr;

#[derive(Clone)]
struct AppState {
    script_path: Arc<String>,
    output: OutputArgs,
}

#[derive(Debug, Args)]
pub struct WindowsArgs {
    /// 指定ps1脚本路径
    #[arg(short, long)]
    pub file: Option<String>,
    /// 修改端口，默认3000
    #[arg(short, long, default_value = "3000")]
    pub port: u16,
    /// 绑定本机IP，默认自动识别，多网卡可能异常
    #[arg(short, long)]
    pub ip: Option<String>,

    #[command(flatten)]
    pub output: OutputArgs,
}

pub async fn run(args: &WindowsArgs) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let script_path = args.file.clone().unwrap_or_else(|| "windows.ps1".to_string());
    // 获取本机 IP 地址
    let local_ip = match &args.ip {
    Some(ip_str) => IpAddr::from_str(ip_str)?,
    None => local_ip()?,
    };
    println!("当前接收绑定IP地址为：{local_ip}");
    let report_url = format!("http://{}:{}/report", local_ip,&args.port);
    let mut script_content = stdfs::read_to_string(&script_path)
        .unwrap_or_else(|_| String::new());

    let url_line = format!("$url = \"{}\"\n", report_url);

    // 使用简单的正则替换或插入（你也可以使用更精确的处理）
    if script_content.contains("$url = ") {
        script_content = script_content
            .lines()
            .map(|line| {
                if line.trim_start().starts_with("$url = ") {
                    url_line.clone()
                } else {
                    format!("{}\n", line)
                }
            })
            .collect();
    } else {
        // 没有 $url 定义，插入到文件开头
        script_content = format!("{}\n{}", url_line, script_content);
    }
    stdfs::write(&script_path, script_content)?;

    ensure_module_output_dir(&args.output, "windows")?;

    let state = AppState {
        script_path: Arc::new(script_path),
        output: args.output.clone(),
    };

    let app = Router::new()
        .route("/script", get(get_script))
        .route("/windows", get(get_windows_script))
        .route("/report", post(report_result))
        .with_state(state);

    let addr = SocketAddr::from(([0, 0, 0, 0], args.port));
    println!("Server running at http://{}", addr);

    // 使用 hyper 0.14 的 listener 和 Server
    let listener = AddrIncoming::bind(&addr)?;
    Server::builder(listener)
        .serve(app.into_make_service_with_connect_info::<SocketAddr>())
        .await?;

    Ok(())
}

async fn get_windows_script(State(state): State<AppState>) -> Response {
    match stdfs::read_to_string(&*state.script_path) {
        Ok(script) => {
            let mut headers = HeaderMap::new();
            headers.insert(
                header::CONTENT_TYPE,
                HeaderValue::from_static("application/octet-stream"),
            );
            headers.insert(
                header::CONTENT_DISPOSITION,
                HeaderValue::from_static("attachment; filename=\"windows.ps1\""),
            );
            (headers, script).into_response()
        }
        Err(_) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            "无法读取 PowerShell 脚本".to_string(),
        )
            .into_response(),
    }
}

async fn get_script(State(state): State<AppState>) -> Response {
    match stdfs::read(&*state.script_path) {
        Ok(bytes) => {
            let (cow, _, had_errors) = UTF_16LE.decode(&bytes);
            if had_errors {
                eprintln!("编码错误: 无法以 UTF-16LE 解码");
                return (StatusCode::INTERNAL_SERVER_ERROR, "文件编码有误，无法正确解码").into_response();
            }
            let mut res = (StatusCode::OK, cow.into_owned()).into_response();
            res.headers_mut().insert(
                header::CONTENT_TYPE,
                header::HeaderValue::from_static("text/plain; charset=utf-8"),
            );
            res
        }
        Err(e) => {
            eprintln!("读取脚本失败: {}", e);
            (StatusCode::NOT_FOUND, format!("读取脚本失败: {}", e)).into_response()
        }
    }
}

async fn report_result(
    State(state): State<AppState>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    Json(payload): Json<Value>,
) -> impl IntoResponse {
    let ip = addr.ip().to_string();
    let filename = format!("{}.json", ip);
    let output_dir = ensure_module_output_dir(&state.output, "windows").expect("创建目录失败");
    let filepath = output_dir.join(filename);
    println!("已获取客户端: {}数据", ip);
    let to_write = if state.output.sanitize {
        sanitize_json(payload)
    } else {
        payload
    };
    match serde_json::to_string_pretty(&to_write) {
        Ok(pretty) => {
            if let Err(e) = fs::write(&filepath, pretty).await {
                eprintln!("写入文件失败: {}", e);
            }
        }
        Err(e) => {
            eprintln!("JSON格式化错误: {}", e);
        }
    }

    "报告接收成功"
}
