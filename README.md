# gxrtools


## 网络测试模块
### Ping

默认结果存储至output/ping/日期.xlsx中

~~~bash
# 参数
执行 ping 操作

Usage: gxtools.exe net ping [OPTIONS] --target <TARGET>

Options:
  -t, --target <TARGET>            IP地址或网段（CIDR），如：192.168.1.1 或 192.168.1.0/24
  -T, --timeout <TIMEOUT>          超时时间（秒） [default: 2]
  -c, --concurrency <CONCURRENCY>  最大并发数 [default: 100]
  -e, --echo                       是否打印结果到终端
  -h, --help                       Print help

# 例子
gxtools.exe net ping -t 192.168.100.1,192.168.100.3-5,192.168.200.1/24
~~~

### Trace 待完善，当前无法解析返回包

~~~bash
# 参数
执行路由追踪操作

~~~


## 等保核查模块

### Linux（ssh方式）

默认存储于output/ssh/ip.json

~~~bash
# 参数
Usage: gxtools.exe check linux [OPTIONS]

Options:
  -H, --host <HOST>                        远程主机的IP地址 (与 -f 互斥)
  -f, --file <FILE>                        从Excel文件读取主机列表(格式: 主机,端口,用户名,密码/密钥路径) (与 -H 互斥)
  -P, --port <PORT>                        SSH端口号 (当使用 -H 时有效) [default: 22]
  -u, --username <USERNAME>                用户名 (当使用 -H 时有效) [default: root]
  -p, --password-or-key <PASSWORD_OR_KEY>  密码或私钥路径 (当使用 -H 时必需)
  -c, --commands <COMMANDS>...             要执行的命令
  -t, --threads <THREADS>                  并发线程数 [default: 4]
  -e, --echo                               输出到控制台，使用前提需指定自定义命令
  -h, --help                               Print help
  
# 例子
gxtools.exe check linux -H 192.168.100.1 -P 22 -p mima -u root -e -c "pwd"
gxtools.exe check linux -f linux.xlsx		# 默认命令
gxtools.exe check linux -f linux.xlsx -c "ls" -e
~~~

### windows

默认存储于output/windows/ip.json，依赖windows中powershell版本，需根据需求手动调整powershell脚本，脚本编码UTF-16LE

~~~bash
# 参数
Usage: gxtools.exe check windows [OPTIONS]

Options:
  -f, --file <FILE>  指定ps1脚本路径
  -p, --port <PORT>  修改端口，默认3000 [default: 3000]
  -i, --ip <IP>      绑定本机IP，默认自动识别，多网卡可能异常
  -h, --help         Print help

# 例子
gxtools.exe check windows		# 默认运行，自动识别网卡，使用本机3000端口
gxtools.exe check windows -i 192.168.1.1 -p 12321		# 绑定网卡，并使用12321端口
~~~

~~~bash
登录windows之后使用powershell执行以下命令，修改ip和端口

iex (Invoke-RestMethod -Uri "http://192.168.101.97:3000/script")
~~~



### MySQL

默认存储于output/mysql/ip.json

~~~bash
# 参数
Usage: gxtools.exe check mysql [OPTIONS] --host <HOST> --password <PASSWORD>

Options:
  -H, --host <HOST>             远程主机的IP地址 (与 -f 互斥)
  -f, --file <FILE>             从Excel文件读取主机列表 (格式: 主机,端口,用户名,密码) (与 -H 互斥)
  -P, --port <PORT>             MySQL端口号 (当使用 -H 时有效) [default: 3306]
  -u, --username <USERNAME>     用户名 (当使用 -H 时有效) [default: root]
  -p, --password <PASSWORD>     密码 (当使用 -H 时必需)
      --yaml <YAML>             自定义yaml文件 [default: cmd.yaml]
  -c, --commands <COMMANDS>...  要执行的SQL命令，多命令时，每个命令使用一个-c
  -t, --threads <THREADS>       并发线程数 [default: 4]
  -e, --echo                    输出到控制台，使用前提需指定自定义命令
  -h, --help                    Print help
  
# 例子
gxtools.exe check mysql -H 192.168.100.1 -P 3306 -p mima  -e -c "select version()"
gxtools.exe check mysql -f mysql.xlsx		# 默认命令
gxtools.exe check mysql -f mysql.xlsx -c "ls" -e
~~~



### Oracle

默认存储于output/oracle/ip.json，使用oracle依赖oci等工具，需再oracle官网中进行下载，并放置于instantclient目录下
>下载路径https://download.oracle.com/otn/nt/instantclient/122010/instantclient-basic-windows.x64-12.2.0.1.0.zip

~~~bash
# 参数
Usage: gxtools.exe check oracle [OPTIONS] --host <HOST> --password <PASSWORD>

Options:
  -H, --host <HOST>                  远程主机的IP地址 (与 -f 互斥)
  -f, --file <FILE>                  从Excel文件读取主机列表 (格式: 主机,端口,用户名,密码) (与 -H 互斥)
  -P, --port <PORT>                  Oracle端口号 (当使用 -H 时有效) [default: 1521]
  -u, --username <USERNAME>          用户名 (当使用 -H 时有效) [default: system]
  -p, --password <PASSWORD>          密码 (当使用 -H 时必需)
  -s, --service-name <SERVICE_NAME>  自定义服务名 [default: ORCL]
      --yaml <YAML>                  自定义yaml文件 [default: cmd.yaml]
  -c, --commands <COMMANDS>...       要执行的SQL命令，多命令时，每个命令使用一个-c
  -t, --threads <THREADS>            并发线程数 [default: 4]
  -e, --echo                         输出到控制台，使用前提需指定自定义命令
  -h, --help                         Print help

  
# 例子
gxtools.exe check oracle -H 192.168.100.1 -P 1521 -p mima  -e -c 'SELECT * FROM v$version'
gxtools.exe check oracle -f oracle.xlsx		# 默认命令
~~~

### Redis

默认存储于output/redis/ip.json

~~~bash
# 参数
执行 Redis 命令（等保基线采集）

Usage: gxtools.exe check redis [OPTIONS] --host <HOST>

Options:
  -H, --host <HOST>
  -P, --port <PORT>          [default: 6379]
  -p, --password <PASSWORD>  [default: ]
  -h, --help                 Print help

  
# 例子
gxtools.exe check redis -H 192.168.1.1 -P 6379 -p redis_pass 
~~~

## 渗透测试模块
### 端口扫描

默认存储于output/portscan/时间戳.json

~~~bash
# 参数
Usage: gxtools.exe pentest portscan [OPTIONS] --targets <TARGETS>

Options:
  -t, --targets <TARGETS>          IP 或 IP 段（支持CIDR、范围、多个IP用逗号隔开）
  -p, --ports <PORTS>              自定义端口（用逗号隔开，例如：80,443,22）
      --full                       是否扫描全部端口（1-65535）
  -c, --concurrency <CONCURRENCY>  最大并发数 [default: 1000]
      --output                     输出到excel
  -h, --help                       Print help
  
# 例子
gxtools.exe pentest portscan -t 192.168.100.1
gxtools.exe pentest portscan -t 192.168.1.2,192.168.100.1/24 -p 135,137-139-445
# 全端口，并输出到excel中
gxtools.exe pentest portscan -t 192.168.1.2 --full --output
~~~

### 漏洞探测 待完善，需优化漏洞链接库


~~~bash
# 参数
poc模块测试

Usage: gxtools.exe pentest poctest [OPTIONS] --ip <IP>

Options:
  -i, --ip <IP>      目标 IP 地址
  -p, --port <PORT>  端口号（可选）
      --poc <POC>    指定漏洞名称（即.so 文件名，不含后缀）
  -h, --help         Print help
~~~

### url路径探测

~~~bash
# 参数
URL 路径探测

Usage: gxtools.exe pentest urlscan [OPTIONS] --url <URL>

Options:
  -u, --url <URL>    目标 URL，如 http://example.com
  -d, --dict <DICT>  字典文件路径 [default: urlscan.txt]
  -h, --help         Print help
~~~

### url页面截图

需要有chrome无头浏览器支持
>下载地址如下 https://github.com/ungoogled-software/ungoogled-chromium-windows

~~~bash
# 参数
URL截图

Usage: gxtools.exe pentest screenshot [OPTIONS] --url-file <URL_FILE>

Options:
  -u, --url-file <URL_FILE>        包含URL列表的文件路径
  -o, --output <OUTPUT>            输出目录 [default: screenshots]
      --concurrency <CONCURRENCY>  并发任务数 [default: 4]
      --path <PATH>                指定无头浏览器位置 [default: ./chromiumoxide/chrome.exe]
~~~

