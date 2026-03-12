use serde::Deserialize;
use std::collections::HashMap;
use std::fs;
use std::path::Path;

/// 从YAML文件加载命令列表
///
/// # 参数
/// * `path` - YAML文件路径
/// * `command_type` - 要加载的命令类型（如 "linux_commands", "windows_commands" 等）
///
/// # 返回
/// * `Vec<String>` - 命令列表，如果失败则返回空向量
///
/// # 示例
/// ```no_run
/// use gxtools::constants::load_commands_from_yaml;
/// let commands = load_commands_from_yaml("cmd.yaml", "linux_commands");
/// for cmd in commands {
///   println!("执行命令: {}", cmd);
/// }
/// ```
pub fn load_commands_from_yaml(path: &str, command_type: &str) -> Vec<String> {
    // 检查文件是否存在
    if !Path::new(path).exists() {
        eprintln!("❌ YAML 文件不存在: {}", path);
        return vec![];
    }

    // 读取文件内容
    let content = match fs::read_to_string(path) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("❌ 无法读取 YAML 文件 {}: {}", path, e);
            return vec![];
        }
    };

    // 解析YAML
    let config: HashMap<String, Vec<String>> = match serde_yaml::from_str(&content) {
        Ok(cfg) => cfg,
        Err(err) => {
            eprintln!("❌ YAML 解析失败: {}", err);
            return vec![];
        }
    };

    // 获取指定类型的命令
    match config.get(command_type) {
        Some(cmds) => cmds.clone(),
        None => {
            eprintln!("⚠️  未找到命令类型 \"{}\"", command_type);
            let available: Vec<&String> = config.keys().collect();
            eprintln!("✅ 可用的命令类型有: {:?}", available);
            vec![]
        }
    }
}

/// 通用配置加载器，支持泛型反序列化
///
/// # 类型参数
/// * `T` - 实现了 `Deserialize` trait 的配置结构体类型
///
/// # 参数
/// * `path` - YAML文件路径
///
/// # 返回
/// * `Result<T, String>` - 反序列化后的配置对象或错误信息
///
/// # 示例
/// ```no_run
/// use serde::Deserialize;
/// use gxtools::constants::load_config;
/// #[derive(Deserialize)]
/// struct AppConfig {
///   timeout: u64,
///   retry: u32,
/// }
/// let _config: AppConfig = load_config("config.yaml").unwrap();
/// ```
pub fn load_config<T>(path: &str) -> Result<T, String>
where
    T: for<'de> Deserialize<'de>,
{
    if !Path::new(path).exists() {
        return Err(format!("配置文件不存在: {}", path));
    }

    let content =
        fs::read_to_string(path).map_err(|e| format!("读取配置文件失败 {}: {}", path, e))?;

    serde_yaml::from_str(&content).map_err(|e| format!("YAML解析失败: {}", e))
}

/// 默认命令配置文件路径
pub const DEFAULT_CMD_CONFIG: &str = "cmd.yaml";

/// 默认指纹配置文件路径
pub const DEFAULT_FINGERPRINT_CONFIG: &str = "fingerprints.yaml";

/// 默认输出目录
pub const DEFAULT_OUTPUT_DIR: &str = "output";

/// 默认超时时间（秒）
pub const DEFAULT_TIMEOUT_SECS: u64 = 10;

/// 默认并发数
pub const DEFAULT_CONCURRENCY: usize = 100;

/// 默认重试次数
pub const DEFAULT_RETRY_COUNT: u32 = 3;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_load_commands_empty_on_missing_file() {
        let commands = load_commands_from_yaml("nonexistent.yaml", "linux_commands");
        assert_eq!(commands, Vec::<String>::new());
    }

    #[test]
    fn test_load_commands_empty_on_invalid_type() {
        // 这个测试需要一个实际的测试文件
        // 在实际使用中，可以创建临时文件进行测试
    }
}
