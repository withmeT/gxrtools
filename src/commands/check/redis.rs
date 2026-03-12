use crate::utils::{OutputArgs, ensure_module_output_dir, sanitize_json};
use clap::Parser;
use redis::{Client, RedisResult, aio::MultiplexedConnection};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::error::Error;
use std::fs::File;
use std::io::Write;

/// 采集参数
#[derive(Parser, Debug, Clone)]
#[command(about = "Redis 基线采集（远程连接）")]
pub struct RedisArgs {
    #[arg(short = 'H', long)]
    pub host: String,
    #[arg(short = 'P', long, default_value = "6379")]
    pub port: u16,
    #[arg(short = 'p', long, default_value = "")]
    pub password: String,

    #[command(flatten)]
    pub output: OutputArgs,
}

#[derive(Serialize, Deserialize)]
struct RedisBaseline {
    config: HashMap<String, String>,
    info: HashMap<String, String>,
    acl_list: Option<Vec<String>>,
    acl_log: Option<Vec<String>>,
    acl_users: Option<Vec<String>>,
    acl_user_detail: Option<HashMap<String, HashMap<String, String>>>,
}

fn save_result(
    host: &str,
    output: &OutputArgs,
    result: serde_json::Value,
) -> Result<(), Box<dyn Error + Send + Sync>> {
    let output_dir = ensure_module_output_dir(output, "redis")?;
    let filename = format!("{}.json", host.replace(".", "_"));
    let filepath = output_dir.join(filename);

    let mut file = File::create(filepath)?;
    let to_write = if output.sanitize {
        sanitize_json(result)
    } else {
        result
    };
    write!(file, "{}", serde_json::to_string_pretty(&to_write)?)?;
    Ok(())
}

async fn try_acl_list(conn: &mut MultiplexedConnection) -> RedisResult<Option<Vec<String>>> {
    match redis::cmd("ACL").arg("LIST").query_async(conn).await {
        Ok(v) => Ok(Some(v)),
        Err(_) => Ok(None), // 兼容 redis 5 没有 ACL
    }
}

async fn try_acl_users(conn: &mut MultiplexedConnection) -> RedisResult<Option<Vec<String>>> {
    match redis::cmd("ACL").arg("USERS").query_async(conn).await {
        Ok(v) => Ok(Some(v)),
        Err(_) => Ok(None),
    }
}

async fn try_acl_log(conn: &mut MultiplexedConnection) -> RedisResult<Option<Vec<String>>> {
    match redis::cmd("ACL")
        .arg("LOG")
        .arg("10")
        .query_async(conn)
        .await
    {
        Ok(v) => Ok(Some(v)),
        Err(_) => Ok(None),
    }
}

async fn try_acl_user_detail(
    conn: &mut MultiplexedConnection,
    users: &[String],
) -> RedisResult<Option<HashMap<String, HashMap<String, String>>>> {
    let mut map = HashMap::new();
    for u in users {
        if let Ok(redis::Value::Array(items)) = redis::cmd("ACL")
            .arg("GETUSER")
            .arg(u)
            .query_async::<redis::Value>(conn)
            .await
        {
            // redis 6+ ACL GETUSER 返回 [ "flags", [flag1,flag2], "passwords", ["<hashed>"], ... ]
            let mut detail = HashMap::new();
            let mut i = 0;
            while i + 1 < items.len() {
                if let redis::Value::BulkString(k) = &items[i] {
                    let key = String::from_utf8_lossy(k).to_string();
                    let value = match &items[i + 1] {
                        redis::Value::Array(vs) => vs
                            .iter()
                            .filter_map(|v| match v {
                                redis::Value::BulkString(d) => {
                                    Some(String::from_utf8_lossy(d).to_string())
                                }
                                _ => None,
                            })
                            .collect::<Vec<_>>()
                            .join(","),
                        redis::Value::BulkString(d) => String::from_utf8_lossy(d).to_string(),
                        _ => "".to_string(),
                    };
                    detail.insert(key, value);
                }
                i += 2;
            }
            map.insert(u.clone(), detail);
        }
    }
    Ok(Some(map))
}

pub async fn run(args: &RedisArgs) -> Result<(), Box<dyn Error + Send + Sync>> {
    let addr = if args.password.is_empty() {
        format!("redis://{}:{}/", args.host, args.port)
    } else {
        format!("redis://:{}@{}:{}/", args.password, args.host, args.port)
    };

    let client = Client::open(addr)?;
    let mut conn = client.get_multiplexed_async_connection().await?;

    // CONFIG
    let config_vec: Vec<String> = redis::cmd("CONFIG")
        .arg("GET")
        .arg("*")
        .query_async(&mut conn)
        .await?;

    let config: HashMap<String, String> = config_vec
        .chunks(2)
        .filter_map(|chunk| {
            if chunk.len() == 2 {
                Some((chunk[0].clone(), chunk[1].clone()))
            } else {
                None
            }
        })
        .collect();

    // INFO
    let info_raw: String = redis::cmd("INFO").arg("ALL").query_async(&mut conn).await?;

    let info: HashMap<String, String> = info_raw
        .lines()
        .filter(|line| !line.is_empty() && !line.starts_with('#'))
        .filter_map(|line| {
            let parts: Vec<&str> = line.splitn(2, ':').collect();
            if parts.len() == 2 {
                Some((parts[0].to_string(), parts[1].to_string()))
            } else {
                None
            }
        })
        .collect();

    // ACL
    let acl_list = try_acl_list(&mut conn).await?;
    let acl_users = try_acl_users(&mut conn).await?;
    let acl_log = try_acl_log(&mut conn).await?;

    let acl_user_detail = if let Some(users) = &acl_users {
        try_acl_user_detail(&mut conn, users).await?
    } else {
        None
    };

    let baseline = RedisBaseline {
        config,
        info,
        acl_list,
        acl_users,
        acl_log,
        acl_user_detail,
    };

    let json_string = serde_json::to_value(&baseline)?;
    if let Err(e) = save_result(&args.host, &args.output, json_string) {
        eprintln!("⚠️ 无法保存结果: {}", e);
    } else {
        println!(
            "✅ 采集 {} 成功，结果已保存至 {}/{}/redis/",
            &args.host,
            args.output.out,
            args.output.task_id_or_default()
        );
    }

    Ok(())
}
