// src/commands/check/mysql.rs
use crate::constants::load_commands_from_yaml;
use crate::utils::{OutputArgs, create_excel_template, ensure_module_output_dir, sanitize_json};
use calamine::{Reader, Xlsx, open_workbook};
use clap::Parser;
use mysql_async::prelude::*;
use mysql_async::{Opts, Pool};
use serde::Serialize;
use serde_json::{Value, json};
use std::error::Error;
use std::fs::File;
use std::io::Write;
use std::path::Path;
use std::time::Instant;
use tokio::task;

#[derive(Parser, Debug)]
#[command(about = "MySQL安全配置采集工具", long_about = None)]
pub struct MysqlArgs {
    /// 远程主机的IP地址 (与 -f 互斥)
    #[arg(short = 'H', long, conflicts_with = "file")]
    pub host: Option<String>,

    /// 从Excel文件读取主机列表 (格式: 主机,端口,用户名,密码) (与 -H 互斥)
    #[arg(short = 'f', long, conflicts_with = "host")]
    pub file: Option<String>,

    /// MySQL端口号 (当使用 -H 时有效)
    #[arg(short = 'P', long, default_value = "3306", requires = "host")]
    pub port: u16,

    /// 用户名 (当使用 -H 时有效)
    #[arg(short = 'u', long, default_value = "root", requires = "host")]
    pub username: String,

    /// 密码 (当使用 -H 时必需)
    #[arg(short = 'p', long, requires = "host")]
    pub password: String,

    /// 自定义yaml文件
    #[arg(long, default_value = "cmd.yaml")]
    pub yaml: String,

    /// 要执行的SQL命令，多命令时，每个命令使用一个-c
    #[arg(short = 'c', long, num_args = 1..)]
    pub commands: Vec<String>,

    /// 并发线程数
    #[arg(short = 't', long, default_value = "4")]
    pub threads: usize,

    /// 输出到控制台，使用前提需指定自定义命令
    #[arg(short = 'e', long, requires = "commands")]
    pub echo: bool,

    #[command(flatten)]
    pub output: OutputArgs,
}

#[derive(Debug, Clone)]
pub struct DbInstanceInfo {
    host: String,
    port: u16,
    username: String,
    password: String,
}

#[derive(Debug, Serialize)]
struct QueryResult {
    status: String,
    output: String,
}
pub async fn run(args: &MysqlArgs) -> Result<(), Box<dyn Error + Send + Sync>> {
    let start_time = Instant::now();
    let db_list = if let Some(file) = &args.file {
        read_hosts_from_excel(file)?
    } else {
        vec![DbInstanceInfo {
            host: args.host.clone().unwrap(),
            port: args.port,
            username: args.username.clone(),
            password: args.password.clone(),
        }]
    };

    ensure_module_output_dir(&args.output, "mysql")?;
    println!("开始执行，共 {} 个实例", db_list.len());

    let queries = if args.commands.is_empty() {
        let cmds = load_commands_from_yaml(&args.yaml, "mysql_commands");
        if cmds.is_empty() {
            eprintln!("❌ 无法加载命令列表");
            return Ok(());
        }
        cmds
    } else {
        args.commands.clone()
    };

    let mut handles = vec![];

    for db in db_list {
        let cmds = queries.clone();
        let echo = args.echo;
        let host = db.host.clone();
        let output = args.output.clone();
        handles.push(task::spawn(async move {
            let result = match connect_and_execute(&db, &cmds, echo).await {
                Ok(json) => json,
                Err(e) => json!({
                    "host": db.host,
                    "error": e.to_string(),
                }),
            };
            let dir = ensure_module_output_dir(&output, "mysql").expect("创建目录失败");
            let filename = format!("{}.json", db.host.replace(".", "_"));
            let filepath = dir.join(filename);
            let to_write = if output.sanitize {
                sanitize_json(result)
            } else {
                result
            };
            let mut file = File::create(filepath).unwrap();
            file.write_all(serde_json::to_string_pretty(&to_write).unwrap().as_bytes())
                .unwrap();
            // 根据返回内容判断是否有错误
            if let Some(err_msg) = to_write.get("error") {
                println!("❌ [{}] 采集失败，原因: {}", host, err_msg);
            } else {
                println!("✅ [{}] 采集完成", host);
            }
        }));
    }

    for h in handles {
        h.await?;
    }

    println!(
        "✅ 所有任务完成，用时 {:.2}s",
        start_time.elapsed().as_secs_f64()
    );
    Ok(())
}

async fn connect_and_execute(
    db: &DbInstanceInfo,
    commands: &[String],
    echo: bool,
) -> Result<Value, Box<dyn Error + Send + Sync>> {
    let url = format!(
        "mysql://{}:{}@{}:{}/mysql",
        db.username, db.password, db.host, db.port
    );
    let opts = Opts::from_url(&url)?; // &url 是 &str
    let pool = Pool::new(opts);
    let mut conn = pool.get_conn().await?;

    let mut output = serde_json::Map::new();

    for cmd in commands {
        match conn.query(cmd).await {
            Ok(rows) => {
                let formatted_rows: Vec<String> = rows
                    .into_iter()
                    .map(|row: mysql_async::Row| format!("{:?}", row))
                    .collect();

                if echo {
                    println!("[{}] {}", db.host, cmd);
                    for line in &formatted_rows {
                        println!("{}", line);
                    }
                }

                output.insert(
                    cmd.clone(),
                    json!(QueryResult {
                        status: "✅ 成功".to_string(),
                        output: formatted_rows.join("\n"),
                    }),
                );
            }
            Err(e) => {
                output.insert(
                    cmd.clone(),
                    json!(QueryResult {
                        status: "❌ 错误".to_string(),
                        output: e.to_string(),
                    }),
                );
            }
        }
    }

    conn.disconnect().await?;
    Ok(json!({
        "host": db.host,
        "results": output,
    }))
}

fn read_hosts_from_excel<P: AsRef<Path>>(
    path: P,
) -> Result<Vec<DbInstanceInfo>, Box<dyn Error + Send + Sync>> {
    if !path.as_ref().exists() {
        let _ = create_excel_template(
            &path,
            vec![
                "主机地址".to_string(),
                "端口".to_string(),
                "用户名".to_string(),
                "密码".to_string(),
            ],
        );
        println!("模板已生成，请填写后重新运行：{}", path.as_ref().display());
        std::process::exit(1);
    }

    let mut workbook: Xlsx<_> = open_workbook(path)?;
    let range = workbook
        .worksheet_range("Sheet1")
        .ok_or("找不到 Sheet1")??;

    let mut hosts = vec![];

    for row in range.rows().skip(1) {
        if row.len() < 4 {
            continue;
        }

        let host = row[0].get_string().unwrap_or("").to_string();
        let port = row[1].get_float().unwrap_or(3306.0) as u16;
        let username = row[2].get_string().unwrap_or("root").to_string();
        let password = row[3].get_string().unwrap_or("").to_string();

        if host.is_empty() || password.is_empty() {
            continue;
        }

        hosts.push(DbInstanceInfo {
            host,
            port,
            username,
            password,
        });
    }

    if hosts.is_empty() {
        return Err("Excel 中没有有效的主机数据".into());
    }

    Ok(hosts)
}
