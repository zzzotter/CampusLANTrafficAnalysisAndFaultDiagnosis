# 成员 B 实时分析与主动探测验证记录

验证日期为 2026 年 11 月 28 日。基于 GitHub 主分支 `4af027f` 实现，使用 Windows、Python 3.13.7、Scapy 2.8.0 和 Flask 3.1.3 验证。

## 按分工交付

| 日期 | 成员 B 的交付与验证 |
| --- | --- |
| 11 月 27 日 | `prober.py` 支持网关 ICMP、DNS A 记录查询和 TCP 连接探测。结果记录目标、状态、耗时、错误和最近探测时间。 `LiveState.get_snapshot()` 提供只读状态快照。 |
| 11 月 28 日 | 共用 A 的有界 `pkt_queue`，由单一消费者读取。流量统计与定时探测分别运行。A 的队列丢弃数、转换失败次数和最近错误都进入 C 的快照。 |
| 11 月 29 日准备 | 统计默认最近 60 秒的包数和字节数，复用 DNS 失败和 TCP RST 两条规则。快照沿用 C 的字段，包含告警观测窗口、实际数值、阈值和文字依据。 |
| 11 月 30 日准备 | 已核对状态时间更新、超时后的继续运行、队列统计和线程停止。三个抓包场景及探测失败场景的证据见下表。演示机实网卡联调和现场验收交由团队确认。 |

## 实测结果

将 A 的构造抓包回放转换为队列记录，以当前时间作为回放参考，保留包间时间差。通过 C 现有 Flask 的 `/api/state` 读取快照。

| 场景 | 实测 |
| --- | --- |
| 正常 `normal.pcap` | 11 条队列记录、894 字节、0 条告警。趋势字节合计为 894。 |
| DNS `dns_fail.pcap` | 18 条、1433 字节。设备 `192.168.1.35` 收到 8 次失败响应，达到 60 秒内 5 次的阈值。 |
| TCP `tcp_abnormal.pcap` | 14 条、766 字节。设备 `203.0.113.9` 的 RST 为 4/4，重置率 100%，达到 50% 阈值和 4 包样本量要求。 |
| 本机主动探测 | 环回 ICMP 成功。回环 DNS 服务返回 A 记录时成功，沉默时返回超时。环回 TCP 分别验证了端口可达和连接失败。 |
| 探测超时与持续消费 | 3 秒缩短窗口测试中，267 次状态请求均成功。DNS 超时 0.15 秒时流量仍在更新。保留记录最多 20 条，空闲后窗口包数为 0，停止后后台线程退出。 |
| 离线回归 | `main.py --input samples/normal.pcap` 得到原始 12 包、成功 11 包、跳过 1 包、总流量 894 字节，并生成 JSON 和 CSV。 |

全量测试 **35 项通过**，覆盖乱序旧包、窗口到期归零、快照副本隔离、异常记录处理、趋势和告警上限、采集统计映射，以及探测超时和队列消费并行。

## 运行方式

在项目根目录执行。已有虚拟环境时，可从安装依赖开始。

```cmd
py -3 -m venv .venv
.\.venv\Scripts\python.exe -m pip install -r requirements.txt pytest
.\.venv\Scripts\python.exe -m pytest
.\.venv\Scripts\python.exe prober.py
.\.venv\Scripts\python.exe main.py --input samples/normal.pcap --format both
```

`prober.py` 单独运行时，按 `config.py` 中的 `PROBE_TARGETS` 执行一轮探测。演示机应填写实际网关、DNS 服务地址和外网 TCP 目标。默认 TCP 目标使用 IP 地址，以便在 DNS 异常时单独检查 TCP 连通性。每次探测默认最多等待 2 秒，每 10 秒启动一轮。

## 成员 C 的接入方式

```python
from live_state import LiveState
from sniffer import PacketSniffer
from web.app import app, set_snapshot_provider

sniffer = PacketSniffer(iface=iface)
state = LiveState(sniffer.pkt_queue, sniffer.stats)
sniffer.start()
try:
    state.start()
    set_snapshot_provider(state.get_snapshot)
    app.run(host="127.0.0.1", port=8000, use_reloader=False)
finally:
    sniffer.stop()
    state.stop()
```

`source=live` 表示快照由 B 的工作线程生成。汇总字段为 `updated_at`、`probes`、`window`、`alerts` 和 `queue`。趋势 `trend` 中每点带 `start_time`、`packet_count` 和 `bytes`。时间戳为 Unix 秒，节点探测耗时为毫秒。探测超时时 `latency_ms` 为空，`elapsed_ms` 保留实际等待时间。

默认每秒刷新一次。最多保留 20,000 条分析记录、100 条告警和 61 个趋势点。 `window.truncated` 为真时，表示内存上限淘汰了当前窗口内的数据。 `queue.dropped` 来自 A 的队列丢弃统计，`queue.capture_errors` 对应现有 A 模块的转换失败次数，`queue.last_error` 保留采集错误原因。

## 实机验收

当前验证机没有可用的 Npcap 提供者，以上实时链路结果来自抓包回放和可控的本机探测。演示机准备好指定网卡和权限后，需复核实时包数变化、探测失败时的持续更新，以及程序关闭。DNS 失败和 TCP RST 告警用于提供排查线索。
