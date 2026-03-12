## gxrtools（GX 安全工具箱）

> 提示：本工具会在本地生成测评证据（`output/<task-id>/...`）。证据目录默认已加入 `.gitignore`，请勿将客户数据、真实账号口令字典提交到仓库。

### 快速开始

```bash
# 查看总帮助
gxtools.exe -h

# 查看模块帮助
gxtools.exe net -h
gxtools.exe check -h
gxtools.exe pentest -h
gxtools.exe compliance -h
```

### 输出目录约定

所有模块支持通用输出参数：

- `--out <DIR>`：输出根目录（默认 `output`）
- `--task-id <ID>`：任务 ID（不传则自动生成时间戳）
- `--sanitize <true|false>`：是否脱敏（默认 `true`）

输出结构示例：

```text
output/<task-id>/
  poctest/
    summary.json
    <target>_<plugin-id>.json
  weakpass/
    weakpass_<timestamp>.xlsx
  portscan/
    ...
  windows/
  ssh/
  mysql/
  oracle/
  redis/
```

> 说明：当 `--sanitize true` 时，`summary.json`/单条证据 JSON 会对 `password/token/secret/api_key` 等字段自动脱敏为 `***`；需要复核时可用 `--sanitize false` 输出明文证据（请妥善保存）。

---

## 网络测试模块（`net`）

### Ping（主机存活）

```bash
Usage: gxtools.exe net ping [OPTIONS] --target <TARGET>

Options:
  -t, --target <TARGET>            IP地址或网段（CIDR），如：192.168.1.1 或 192.168.1.0/24
  -T, --timeout <TIMEOUT>          超时时间（秒） [default: 2]
  -c, --concurrency <CONCURRENCY>  最大并发数 [default: 100]
  -e, --echo                       是否打印结果到终端

Example:
gxtools.exe net ping -t 192.168.100.1,192.168.100.3-5,192.168.200.1/24
```

### Trace（路由追踪）

纯 Rust 实现，不调用系统 `traceroute/tracert`。

- Linux/macOS：通过 raw socket 接收 ICMP（通常需要 root）
- Windows：使用 ICMP API 实现逐跳探测（通常需要管理员权限）

```bash
Usage: gxtools.exe net trace [OPTIONS] --target <TARGET>

Options:
  -t, --target <TARGET>  目标主机（IP 或域名，仅 IPv4）
  -m, --max-hops <N>     最大跳数 [default: 30]
  -T, --timeout <SECS>   每跳超时（秒） [default: 3]
  -q, --nqueries <N>     每跳探测次数（用于 RTT） [default: 3]

Example:
gxtools.exe net trace -t 8.8.8.8
gxtools.exe net trace -t baidu.com -m 20
```

---

## 等保核查模块（`check`）

### Linux（SSH 方式）

默认输出到 `output/<task-id>/ssh/`。

```bash
Usage: gxtools.exe check linux [OPTIONS]

Options:
  -H, --host <HOST>                        远程主机IP（与 -f 互斥）
  -f, --file <FILE>                        Excel 主机列表（与 -H 互斥）
  -P, --port <PORT>                        SSH 端口 [default: 22]
  -u, --username <USERNAME>                用户名 [default: root]
  -p, --password-or-key <PASSWORD_OR_KEY>  密码或私钥路径
  -c, --commands <COMMANDS>...             自定义命令（可多个 -c）
  -t, --threads <THREADS>                  并发线程数 [default: 4]
  -e, --echo                               输出到控制台（通常配合 -c）
      --out <OUT>                          输出根目录 [default: output]
      --task-id <TASK_ID>                  任务ID
      --sanitize <true|false>              输出脱敏 [default: true]

Examples:
gxtools.exe check linux -H 192.168.100.1 -P 22 -u root -p mima -e -c "pwd"
gxtools.exe check linux -f linux.xlsx
gxtools.exe check linux -f linux.xlsx -c "ls" -e
```

### Windows（本地脚本下发/采集）

默认输出到 `output/<task-id>/windows/`。PowerShell 脚本编码建议 `UTF-16LE`（按需调整脚本内容）。

```bash
Usage: gxtools.exe check windows [OPTIONS]

Options:
  -f, --file <FILE>            指定 ps1 脚本路径
  -p, --port <PORT>            本机 HTTP 服务端口 [default: 3000]
  -i, --ip <IP>                绑定本机 IP（多网卡时可手动指定）
      --out <OUT>              输出根目录 [default: output]
      --task-id <TASK_ID>      任务ID
      --sanitize <true|false>  输出脱敏 [default: true]

Examples:
gxtools.exe check windows
gxtools.exe check windows -i 192.168.1.1 -p 12321

# 登录 Windows 目标后执行（替换为你的测评机 IP/端口）
iex (Invoke-RestMethod -Uri "http://<your-ip>:3000/script")
```

### MySQL / Oracle / Redis（基线采集）

这三类模块支持 `--yaml cmd.yaml`（或用 `-c` 自定义命令/SQL）。默认输出到 `output/<task-id>/<module>/`。

```bash
# MySQL
gxtools.exe check mysql -H 192.168.100.1 -P 3306 -u root -p mima -e -c "SELECT VERSION();"
gxtools.exe check mysql -f mysql.xlsx

# Oracle（需准备 instantclient）
gxtools.exe check oracle -H 192.168.100.1 -P 1521 -u system -p mima -e -c "SELECT * FROM v$version"
gxtools.exe check oracle -f oracle.xlsx

# Redis
gxtools.exe check redis -H 192.168.1.1 -P 6379 -p redis_pass
```

---

## 合规分析与报告（`compliance`）

读取采集结果并生成“差距分析”报告（当前内置 Redis 自动判定，后续可扩展到 Linux/Windows/MySQL/Oracle）。

```bash
# 统一 task-id 归档采集 + 分析
gxtools.exe check redis -H 192.168.1.10 -P 6379 -p redis_pass --task-id 20260311_a
gxtools.exe compliance analyze --task-id 20260311_a

# 不指定 task-id 时，会自动选择 output/ 下最新的任务目录
gxtools.exe compliance analyze
```

---

## 渗透测试模块（`pentest`）

### Portscan（端口扫描）

默认输出到 `output/<task-id>/portscan/`。

```bash
Usage: gxtools.exe pentest portscan [OPTIONS] --targets <TARGETS>

Options:
  -t, --targets <TARGETS>          IP 或 IP 段（支持 CIDR、范围、多个 IP 用逗号隔开）
  -p, --ports <PORTS>              自定义端口（逗号分隔，如 80,443,22 或 1-1024）
      --full                       扫描全部端口（1-65535）
  -c, --concurrency <CONCURRENCY>  最大并发数 [default: 1000]
      --output                     输出到 Excel

Examples:
gxtools.exe pentest portscan -t 192.168.100.1
gxtools.exe pentest portscan -t 192.168.1.2,192.168.100.1/24 -p 135,137-139,445
gxtools.exe pentest portscan -t 192.168.1.2 --full --output
```

### Weakpass（弱口令扫描）

扫描常见服务的弱口令/空口令（SSH/RDP/Tomcat/Nacos 等）。命中时会输出用户名与密码；如需在结果文件中脱敏，请用 `--sanitize true`（默认）。

```bash
Usage: gxtools.exe pentest weakpass [OPTIONS] --targets <TARGETS>

Examples:
gxtools.exe pentest weakpass -t 192.168.1.0/24 -s all -c 20 -T 5 -o
gxtools.exe pentest weakpass -t 192.168.1.10 -s ssh -u usernames.txt -p passwords.txt --sanitize false
```

### PocTest（漏洞探测 / POC 验证）

支持加载 `./plugins` 下的 YAML 插件批量验证目标。命中项会落盘到 `output/<task-id>/poctest/`，并生成汇总 `summary.json`；可选导出 Excel（仅命中项）。

```bash
Usage: gxtools.exe pentest poctest [OPTIONS]

常用参数：
  -t, --target <TARGET>            单个目标（与 --targets/--file 互斥）
      --targets <TARGETS>          多目标（逗号分隔；CIDR/范围仅 IPv4）
  -f, --file <FILE>                文件导入目标（每行一个）
      --plugin <PLUGIN>            插件路径（目录或单个 YAML）[default: ./plugins]
  -c, --concurrency <CONCURRENCY>  最大并发数 [default: 50]
      --excel                      导出命中项到 Excel
  -v, --verbose                    输出详细信息
      --sanitize <true|false>      是否脱敏 [default: true]

Examples:
gxtools.exe pentest poctest --targets 192.168.1.1,192.168.1.2 --excel
gxtools.exe pentest poctest -f targets.txt --plugin .\\plugins\\es_unauth_v2.yaml --sanitize false
```

#### 插件格式（推荐：V2）

建议按 `plugins/es_unauth_v2.yaml` 的结构新增插件。HTTP 类插件支持多 step、`any` 逻辑、请求头/Body、超时与端口覆盖。

对于“弱口令/默认口令（Basic Auth）”类插件：

- 在每个 step 增加 `credential: "user:pass"`（允许空密码如 `"elastic:"`）
- 命中后会把 `username/password` 写入输出（默认 `--sanitize true` 会脱敏；复核用 `--sanitize false` 输出明文）

V2 通用模板（复制后按需改）：

```yaml
id: your_vuln_id
name: 你的漏洞名称
transport: http
port: 80
severity: medium
tags: ["web"]

http:
  scheme: http
  any: false
  requests:
    - method: GET
      path: /path
      timeout: 5
      headers:
        User-Agent: "gxtools-poctest"
      matchers:
        - type: status
          status: 200
        - type: body_contains
          contains: "keyword"
```

### Urlscan（URL 路径探测）

```bash
Usage: gxtools.exe pentest urlscan [OPTIONS] --url <URL>

Options:
  -u, --url <URL>    目标 URL，如 http://example.com
  -d, --dict <DICT>  字典文件路径 [default: urlscan.txt]
```

### Screenshot（URL 页面截图）

需要无头浏览器支持（可使用 [ungoogled-chromium-windows](https://github.com/ungoogled-software/ungoogled-chromium-windows)）。

```bash
Usage: gxtools.exe pentest screenshot [OPTIONS] --url-file <URL_FILE>

Options:
  -u, --url-file <URL_FILE>        包含 URL 列表的文件路径
  -o, --output <OUTPUT>            输出目录 [default: screenshots]
      --concurrency <CONCURRENCY>  并发任务数 [default: 4]
      --path <PATH>                无头浏览器位置 [default: ./chromiumoxide/chrome.exe]
```

