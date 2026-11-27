# 局域网流量分析与故障诊断系统

一个面向校园网和小型局域网排查场景的网络课程项目。系统读取 PCAP 抓包文件，解析常见网络协议，统计设备与协议流量，并根据可解释的规则发现 DNS 或 TCP 故障线索，最后展示和导出分析结果。

> 当前项目定位为课程设计原型。它根据抓包内容提供排查线索，不代替专业网络监控或安全产品。

## 功能目标

- 读取 PCAP/PCAPNG 抓包文件。
- 解析常见 Ethernet、IPv4、TCP、UDP 和 DNS 数据。
- 展示总包数、总流量、协议分布、设备流量排行和时间趋势。
- 检测至少两类异常，例如 DNS 请求失败、TCP 连接异常或设备流量突增。
- 对每条告警显示涉及设备、时间范围、触发指标和判断依据。
- 将分析结果导出为 JSON 或 CSV。
- 对文件不存在、空文件、损坏文件和无法识别的数据包给出明确提示。

## 环境要求

- Python 3.10 或更高版本
- Windows、macOS 或 Linux
- 用于解析抓包的 Python 依赖（以项目中的 `requirements.txt` 为准）

依赖：

- `scapy`：读取和解析抓包文件（唯一的运行时依赖）
- `pytest`：运行测试（开发依赖，见 `pyproject.toml`）

> 统计、时间趋势与导出全部用 Python 标准库实现（`collections`、`json`、`csv`），不引入 pandas/matplotlib。

## 安装

在项目根目录打开终端：

```bash
python -m venv .venv
```

Windows PowerShell：

```powershell
.venv\Scripts\Activate.ps1
```

macOS / Linux：

```bash
source .venv/bin/activate
```

安装依赖：

```bash
pip install -r requirements.txt
```

运行测试还需要测试依赖（`pytest`，已写入 `pyproject.toml` 的 `dev` 组）：

```bash
pip install pytest
```

## 运行

```bash
python main.py --input samples/normal.pcap --output reports
```

参数：

| 参数 | 默认值 | 说明 |
| --- | --- | --- |
| `--input` | 必填 | PCAP/PCAPNG 文件路径 |
| `--output` | `reports` | 导出目录 |
| `--format` | `both` | `json` / `csv` / `both` |
| `--max-packets` | 不限 | 最多解析多少个包，用于大文件快速预览 |
| `--top` | `10` | 设备流量排行显示前 N 名 |

查看帮助：

```bash
python main.py --help
```

程序运行后会输出：

1. 抓包文件基本信息及解析覆盖率；
2. 总包数、总流量和协议分布；
3. 设备流量排行及时间趋势；
4. 异常告警及其判断依据；
5. 导出报告的保存位置。

文件不存在、空文件、损坏文件时，程序打印一句中文错误并以退出码 `2` 结束，不打印堆栈。

本项目当前是命令行程序；若后续增加网页界面，请在此补充启动命令、访问地址和页面操作步骤。

## 示例输出

以下是一次**真实运行**的完整输出（`python main.py --input samples\normal.pcap --output reports`，Windows 终端）：

```text
分析文件：samples\normal.pcap
原始包数：12　解析覆盖率：91.67%（成功 11 + 部分 0，跳过 1）
总流量：894 B　解析耗时：6.5 ms
跳过原因：ARP 等非 IP 数据包=1

协议分布：
  TCP          7 包
  UDP          4 包

设备流量排行（前 10）：
  192.168.1.20    合计      828 B　发送 400 B　接收 428 B
  93.184.216.34   合计      585 B　发送 322 B　接收 263 B
  114.114.114.114 合计      181 B　发送 106 B　接收 75 B
  fe80::1         合计       66 B　发送 66 B　接收 0 B
  fe80::2         合计       66 B　发送 0 B　接收 66 B
  192.168.1.2     合计       62 B　发送 0 B　接收 62 B

时间趋势（每个时间桶的包数/流量）：
  2026-11-24 17:17:00      11 包       894 B

异常告警（0 条）：
  未发现异常线索

导出文件：
  reports\normal_report.json
  reports\normal_devices.csv
  reports\normal_alerts.csv
  reports\normal_trend.csv
```

换用异常样例 `dns_fail.pcap`，告警段变成（同样取自真实运行）：

```text
异常告警（1 条）：
  [DNS 失败] 设备 192.168.1.35　2026-11-24 17:17:37 ~ 2026-11-24 17:17:37
    依据：60 秒内收到 8 次 DNS 失败响应，阈值为 5 次
```

每条告警都带四要素：规则名（`DNS 失败`）、涉及设备、时间范围、触发依据（实际值 + 阈值 + 窗口）。
异常样例的完整输出与导出文件见 `docs/report/第2天_C_集成与错误提示验证.md`。

### 导出文件说明

| 文件 | 内容 |
| --- | --- |
| `<文件名>_report.json` | 整份结果：`source`、`stats`（解析质量）、`summary`（总量/协议/设备排行）、`trend`（时间趋势）、`alerts`（告警） |
| `<文件名>_devices.csv` | 设备排行：`ip, sent_bytes, received_bytes, total_bytes` |
| `<文件名>_alerts.csv` | 告警：`type, device_ip, start_time, end_time, reason` |
| `<文件名>_trend.csv` | 时间趋势：`start_time, packet_count, bytes` |

CSV 以 UTF-8 BOM 写出，Excel 双击打开中文表头不乱码。

### 错误输入的表现

三种坏输入的提示与退出码（均取自真实运行）：

```text
> python main.py --input samples\empty.pcap
[错误] 文件为空（0 字节）：samples\empty.pcap          # 退出码 2

> python main.py --input samples\corrupt.pcap
[错误] 文件格式无法识别，可能已损坏或不是 PCAP/PCAPNG 文件：samples\corrupt.pcap   # 退出码 2

> python main.py --input samples\不存在的.pcap
[错误] 文件不存在：samples\不存在的.pcap               # 退出码 2
```

程序只打印一句中文提示并以退出码 `2` 结束，不输出 Python 异常栈。

## 项目结构

当前结构（括号内为负责人）：

```text
.
├── main.py                 # 程序入口（C）：参数解析 → 调各模块 → 打印与导出
├── parser.py               # PCAP 读取和协议解析（A）
├── analyzer.py             # 流量统计、时间趋势、异常检测（B）
├── reporter.py             # 终端展示及 JSON/CSV 导出（C）
├── config.py               # 检测阈值、时间桶宽等配置（B）
├── conftest.py             # 让 pytest 找到根目录模块
├── pyproject.toml          # 依赖与 pytest 配置
├── requirements.txt        # 运行时依赖（pip install -r 用）
├── docs/
│   ├── 数据字段规范.md      # 字段契约（唯一真相源）
│   ├── 字段冻结单.md        # A 模块 v1.0 接口冻结与变更流程
│   └── report/             # 各阶段自检、验证与验收记录
├── samples/                # 构造的抓包样例（可重复生成，非真实流量）
├── scripts/
│   ├── gen_samples.py      # 重新生成 samples/ 下的样例
│   ├── pcap_to_pcapng.py   # 从 pcap 派生同内容的 pcapng（保证双格式样例一致）
│   └── day3_check.py       # 字段冻结单要求的冒烟验证
├── tests/                  # pytest 测试代码
└── reports/                # 运行产物（已 gitignore，仅保留 .gitkeep）
```

> `reports/`（程序导出）与 `docs/report/`（人写的验收记录）是两个不同的目录，不要混淆。

## 分析与检测说明

分析流程：

```text
PCAP 文件 → 数据包解析 → 会话与设备统计 → 异常规则检测 → 展示和导出
```

异常规则必须在结果中说明触发依据，包括规则名称、涉及设备、相关时间范围、实际指标值和阈值。阈值应集中配置，并在项目文档中注明默认值。

TCP 重传等行为仅能根据抓包中可见的信息进行近似判断；抓包点、丢包和采集范围都可能影响结果。系统应把判断结果表述为“异常线索”，避免将其当作确定诊断。

## 测试与验收

每份样例的预期包数、覆盖率和跳过数都记录在 `samples/README.md`：

- 正常抓包：`normal.pcap` / `normal.pcapng`（TCP、UDP、DNS、ARP、IPv6）
- 告警抓包：`dns_fail.pcap`（DNS 失败）、`tcp_abnormal.pcap`（TCP 重置率）
- 坏输入：`empty.pcap`、`corrupt.pcap`、`nonip.pcap`、`dns_malformed.pcap`

运行测试与冒烟验证：

```bash
pytest                          # 或 python -m pytest
python scripts/day3_check.py    # 期望输出 4/4
```

验收前应记录每个样例的输入文件、预期结果、实际结果、解析成功数和跳过数，记录写入 `docs/report/`。

## 团队分工

- **成员 A：抓包读取与协议解析**——负责 PCAP 输入、字段提取、协议覆盖和解析错误处理。
- **成员 B：统计与异常检测**——负责流量汇总、检测规则、阈值配置和规则验证。
- **成员 C：界面、报告与集成**——负责启动流程、结果展示、报告导出、文档和最终联调。

## 使用提示

- 请仅分析自己有权访问和处理的抓包数据。
- 抓包可能包含敏感信息；演示时优先使用公开或自行构造的样例。
- 解析器会跳过不支持的数据包；报告中的解析覆盖率可用于判断结果是否完整。
- 不同抓包位置和过滤条件会影响统计与告警结果。

## 当前状态

已完成：

- **解析（A）**：Ethernet / IPv4 / IPv6 / TCP（6 个标志位 + seq/ack/window）/ UDP / DNS；覆盖率、耗时与跳过原因统计；坏输入给出中文提示。
- **统计与检测（B）**：包数、总流量、协议分布、设备排行、时间趋势；DNS 失败规则与 TCP 重置率规则，阈值集中在 `config.py`。
- **集成与导出（C）**：`main.py` 启动流程、终端报告、JSON/CSV 导出。

已知限制：

- 不支持 ICMP 类型/代码细分、TCP 选项、TLS/HTTP 应用层内容、IP 分片重组、VLAN 双标签、非以太网链路类型（如 `tcpdump -i any`）。
- TCP 重传与重置率均为近似判断，只作为“异常线索”，不是确定诊断。
- `ParseStats.protocol_counts` 会把被跳过的包（如 ARP）计入 `OTHER`，与 `analyze_packets` 只统计已解析包的口径不同，两者不要混用。
- 尚未实现“设备流量突增”规则与“TCP SYN 无响应”规则（`tcp_abnormal.pcap` 已备好对应样例）。
 
