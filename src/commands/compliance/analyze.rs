use crate::utils::{OutputArgs, ensure_module_output_dir, save_to_excel_with_base};
use clap::Parser;
use serde::Serialize;
use serde_json::Value;
use std::error::Error;
use std::fs;
use std::path::{Path, PathBuf};

/// 等保合规分析（读取采集结果并生成差距分析报告）
#[derive(Parser, Debug, Clone)]
pub struct AnalyzeArgs {
    /// 采集结果根目录（默认 output）
    #[arg(long, default_value = "output")]
    pub input: String,

    /// 指定要分析的 task-id（不传则自动选择最新的一个）
    #[arg(long)]
    pub task_id: Option<String>,

    /// 只分析 Redis（后续可扩展 mysql/ssh/windows/oracle）
    #[arg(long, default_value_t = true)]
    pub redis: bool,

    /// 输出差距分析 Excel
    #[arg(long, default_value_t = true)]
    pub excel: bool,

    #[command(flatten)]
    pub out: OutputArgs,
}

#[derive(Debug, Serialize, Clone)]
pub struct Finding {
    pub host: String,
    pub check_id: String,
    pub item: String,
    pub status: String, // PASS/FAIL/WARN/NA
    pub severity: String,
    pub evidence: String,
    pub recommendation: String,
}

pub async fn run(args: &AnalyzeArgs) -> Result<(), Box<dyn Error + Send + Sync>> {
    let task_id = args
        .task_id
        .clone()
        .or_else(|| pick_latest_task_id(Path::new(&args.input)));

    let Some(task_id) = task_id else {
        return Err("未找到可分析的任务目录，请先执行 check 模块采集或指定 --task-id".into());
    };

    let input_task_dir = PathBuf::from(&args.input).join(&task_id);
    if !input_task_dir.exists() {
        return Err(format!("输入任务目录不存在: {}", input_task_dir.display()).into());
    }

    let mut findings: Vec<Finding> = Vec::new();

    if args.redis {
        let redis_dir = input_task_dir.join("redis");
        let mut redis_findings = analyze_redis_dir(&redis_dir)?;
        findings.append(&mut redis_findings);
    }

    // 输出目录：默认放到 out/<out_task_id>/compliance
    // 若用户未显式指定 out.task_id，则我们沿用“输入 task_id”，确保同一任务目录里有采集 + 分析
    let mut out = args.out.clone();
    if out.task_id.is_none() {
        out.task_id = Some(task_id.clone());
    }

    let compliance_dir = ensure_module_output_dir(&out, "compliance")?;
    let report_path = compliance_dir.join("report.json");
    fs::write(&report_path, serde_json::to_string_pretty(&findings)?)?;
    println!("✅ 差距分析 JSON 已生成: {}", report_path.display());

    if args.excel {
        let base = out.task_dir();
        save_to_excel_with_base(
            &base,
            "compliance",
            &findings,
            &["Host", "CheckID", "Item", "Status", "Severity", "Evidence", "Recommendation"],
            |f| {
                vec![
                    f.host.clone(),
                    f.check_id.clone(),
                    f.item.clone(),
                    f.status.clone(),
                    f.severity.clone(),
                    f.evidence.clone(),
                    f.recommendation.clone(),
                ]
            },
            "gap_report",
        )?;
    }

    println!("🎉 合规分析完成，共 {} 条发现", findings.len());
    Ok(())
}

fn pick_latest_task_id(output_root: &Path) -> Option<String> {
    let mut dirs: Vec<String> = fs::read_dir(output_root)
        .ok()?
        .filter_map(|e| e.ok())
        .filter(|e| e.path().is_dir())
        .filter_map(|e| e.file_name().to_str().map(|s| s.to_string()))
        .collect();
    dirs.sort();
    dirs.pop()
}

fn analyze_redis_dir(dir: &Path) -> Result<Vec<Finding>, Box<dyn Error + Send + Sync>> {
    if !dir.exists() {
        return Ok(vec![Finding {
            host: "-".to_string(),
            check_id: "REDIS.DIR".to_string(),
            item: "Redis 采集结果目录".to_string(),
            status: "NA".to_string(),
            severity: "info".to_string(),
            evidence: format!("未发现目录: {}", dir.display()),
            recommendation: "如需分析 Redis，请先运行 `gxtools check redis` 采集基线".to_string(),
        }]);
    }

    let mut findings = Vec::new();

    for entry in fs::read_dir(dir)? {
        let entry = entry?;
        let path = entry.path();
        if path.extension().and_then(|s| s.to_str()) != Some("json") {
            continue;
        }

        let host = path
            .file_stem()
            .and_then(|s| s.to_str())
            .unwrap_or("-")
            .replace('_', ".");

        let content = fs::read_to_string(&path)?;
        let v: Value = serde_json::from_str(&content)?;

        let config = v.get("config").and_then(|x| x.as_object());
        let info = v.get("info").and_then(|x| x.as_object());

        // 1) requirepass
        let requirepass = config
            .and_then(|m| m.get("requirepass"))
            .and_then(|x| x.as_str())
            .unwrap_or("");
        findings.push(Finding {
            host: host.clone(),
            check_id: "REDIS.AUTH.1".to_string(),
            item: "Redis 访问控制：requirepass 不应为空".to_string(),
            status: if requirepass.is_empty() { "FAIL" } else { "PASS" }.to_string(),
            severity: if requirepass.is_empty() { "high" } else { "info" }.to_string(),
            evidence: format!("requirepass={}", if requirepass.is_empty() { "<empty>" } else { "***" }),
            recommendation: if requirepass.is_empty() {
                "配置 `requirepass` 或使用 Redis 6+ ACL，禁止匿名访问；并限制来源 IP。".to_string()
            } else {
                "已配置口令；建议进一步启用 ACL 并最小权限。".to_string()
            },
        });

        // 2) protected-mode
        let protected_mode = config
            .and_then(|m| m.get("protected-mode"))
            .and_then(|x| x.as_str())
            .unwrap_or("");
        findings.push(Finding {
            host: host.clone(),
            check_id: "REDIS.NET.1".to_string(),
            item: "Redis 网络暴露：protected-mode 应为 yes".to_string(),
            status: if protected_mode.eq_ignore_ascii_case("yes") {
                "PASS"
            } else if protected_mode.is_empty() {
                "WARN"
            } else {
                "FAIL"
            }
            .to_string(),
            severity: if protected_mode.eq_ignore_ascii_case("yes") {
                "info"
            } else {
                "medium"
            }
            .to_string(),
            evidence: format!("protected-mode={}", if protected_mode.is_empty() { "<missing>" } else { protected_mode }),
            recommendation: "设置 `protected-mode yes`，并通过 bind/防火墙/安全组限制访问来源。".to_string(),
        });

        // 3) bind
        let bind = config
            .and_then(|m| m.get("bind"))
            .and_then(|x| x.as_str())
            .unwrap_or("");
        let bind_is_any = bind.contains("0.0.0.0") || bind.contains("::") || bind.contains("*");
        findings.push(Finding {
            host: host.clone(),
            check_id: "REDIS.NET.2".to_string(),
            item: "Redis 网络暴露：bind 不应为全网监听".to_string(),
            status: if bind.is_empty() {
                "WARN"
            } else if bind_is_any {
                "FAIL"
            } else {
                "PASS"
            }
            .to_string(),
            severity: if bind_is_any { "high" } else { "info" }.to_string(),
            evidence: format!("bind={}", if bind.is_empty() { "<missing>" } else { bind }),
            recommendation: "将 `bind` 限制为管理网段/本机回环，并结合防火墙策略。".to_string(),
        });

        // 4) TLS（可选）
        let tls_port = config
            .and_then(|m| m.get("tls-port"))
            .and_then(|x| x.as_str())
            .unwrap_or("");
        findings.push(Finding {
            host: host.clone(),
            check_id: "REDIS.CRYPTO.1".to_string(),
            item: "Redis 传输加密：建议启用 TLS（视场景）".to_string(),
            status: if tls_port.is_empty() || tls_port == "0" { "WARN" } else { "PASS" }.to_string(),
            severity: if tls_port.is_empty() || tls_port == "0" { "low" } else { "info" }.to_string(),
            evidence: format!("tls-port={}", if tls_port.is_empty() { "<missing>" } else { tls_port }),
            recommendation: "如跨主机/跨网络访问，建议启用 TLS 或通过隧道/内网专线保障传输安全。".to_string(),
        });

        // 附加：版本信息（仅作为信息项）
        let redis_version = info
            .and_then(|m| m.get("redis_version"))
            .and_then(|x| x.as_str())
            .unwrap_or("");
        if !redis_version.is_empty() {
            findings.push(Finding {
                host: host.clone(),
                check_id: "REDIS.INFO.1".to_string(),
                item: "Redis 版本信息".to_string(),
                status: "INFO".to_string(),
                severity: "info".to_string(),
                evidence: format!("redis_version={}", redis_version),
                recommendation: "建议结合官方支持周期与漏洞公告，保持及时更新。".to_string(),
            });
        }
    }

    Ok(findings)
}

