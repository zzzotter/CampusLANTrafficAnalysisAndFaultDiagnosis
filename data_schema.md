# 统一数据字段约定

本文档定义 `parser.py` 输出给 `analyzer.py` 的单个数据包记录格式。解析器应为每个成功解析的数据包生成一个 Python 字典；无法识别或损坏的数据包安全跳过，并由解析器单独统计跳过数量。

## 数据包字段

| 字段名 | Python 类型 | 说明 |
|---|---|---|
| `timestamp` | `float` | Unix 时间戳，单位为秒，可包含小数部分。 |
| `src_ip` | `str` | 源 IP 地址；无法提取时使用空字符串。 |
| `dst_ip` | `str` | 目的 IP 地址；无法提取时使用空字符串。 |
| `src_port` | `int \| None` | 源传输层端口；没有 TCP/UDP 端口时为 `None`。 |
| `dst_port` | `int \| None` | 目的传输层端口；没有 TCP/UDP 端口时为 `None`。 |
| `protocol` | `str` | 传输层协议名称，统一使用大写，如 `TCP`、`UDP`、`ICMP`、`OTHER`。 |
| `length` | `int` | 数据包长度，单位为字节。团队应统一使用抓包记录的原始包长度。 |

## 样例记录

```python
{
    "timestamp": 1732449600.125,
    "src_ip": "192.168.1.10",
    "dst_ip": "8.8.8.8",
    "src_port": 53000,
    "dst_port": 53,
    "protocol": "UDP",
    "length": 78,
}
```

## 模块调用约定

- `parser.py` 建议提供 `parse_pcap(pcap_path)`，返回 `(packets, skipped_count)`。
- `packets` 是上述记录组成的列表，类型可写作 `list[dict]`。
- `skipped_count` 是被安全跳过的数据包数量，类型为 `int`。
- `analyzer.py` 接收 `packets`，统计总包数、总流量、协议分布和设备流量排行。
- `analyzer.py` 的统计包数应基于成功解析的 `packets`；输入文件原始包数可由成功解析数与跳过数相加得到（若解析器能准确计数）。

字段名、类型或返回值如需变更，应同步更新解析器、统计模块、启动入口和本文档。
