# 11 月 25 日 DNS 告警验证结果 成员 B

验证日期 2026 年 11 月 25 日。运行环境为 Python 3.13.7。单元测试共 6 项，全部通过。

## 规则与配置

调用 `analyzer.detect_dns_failures(packets)` 返回告警列表。规则按 DNS 响应包的目的 IP 统计非零响应码。默认窗口为 60 秒，失败次数达到 5 次即告警，可在 `config.py` 调整。每台设备报告失败次数最多的窗口，开始和结束时间分别是该窗口内第一条和最后一条失败响应的时间戳。

## 测试记录

| 样例 | 预期结果 | 实际结果 |
| --- | --- | --- |
| 正常抓包 `samples/normal.pcap` | 0 条 DNS 告警 | 0 条告警。解析返回 11 条记录、跳过 1 条，统计流量 894 字节 |
| 异常抓包 `samples/dns_fail.pcap` | 为 `192.168.1.35` 产生 1 条告警，失败次数为 8 | 1 条告警，设备为 `192.168.1.35`，8 次失败，阈值 5 次 |
| 同一设备 60 秒内失败 4 次 | 0 条告警 | 0 条告警 |
| 同一设备失败 5 次，首末恰好间隔 60 秒 | 1 条告警，计入第 5 次失败 | 1 条告警，失败次数 5 |
| 同一设备失败 5 次，首末间隔 60.001 秒 | 0 条告警，最早一次移出窗口 | 0 条告警 |

## 异常样例的实际告警

时间戳来自抓包样例。换算成北京时间，首末失败响应分别出现在 11 月 24 日 17:17:37.806942 和 17:17:37.814666。

```json
{
  "type": "DNS 失败",
  "device_ip": "192.168.1.35",
  "start_time": 1795511857.806942,
  "end_time": 1795511857.814666,
  "failure_count": 8,
  "window_seconds": 60,
  "threshold": 5,
  "reason": "60 秒内收到 8 次 DNS 失败响应，阈值为 5 次"
}
```

## 复现命令

在仓库根目录使用已经安装项目依赖的 `.venv` 执行。

```cmd
.\.venv\Scripts\python.exe -B -m unittest discover -s tests -v
.\.venv\Scripts\python.exe -B -c "from parser import parse_pcap; from analyzer import detect_dns_failures; print({name: detect_dns_failures(parse_pcap('samples/' + name + '.pcap')[0]) for name in ('normal', 'dns_fail')})"
```
