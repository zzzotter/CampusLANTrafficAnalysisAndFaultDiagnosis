# 测试抓包说明（成员 A 维护）

这些文件由 `生成测试抓包.py` 构造，**可重复生成、不含任何真实流量与隐私信息**，用于解析自测、B 的规则验证、C 的联调与现场验收。

重新生成（在项目根目录执行）：

```bash
python samples/生成测试抓包.py
```

## 样例清单与预期包数

| 文件 | 来源 | 预期包数 | 预期解析结果 | 用途 |
| --- | --- | --- | --- | --- |
| `normal.pcap` | 脚本构造（Ether/IP/TCP/UDP/DNS/ARP/IPv6） | 12 | packets=11、skipped_count=1（ARP），覆盖率 91.67% | 正常流量基线；验证基础字段与协议分布 |
| `dns_fail.pcap` | 脚本构造（8 次失败响应 + 1 次正常） | 18 | packets=18、skipped_count=0，覆盖率 100% | 触发 DNS 失败规则；验证 rcode / 方向解析 |
| `tcp_abnormal.pcap` | 脚本构造（5 SYN 无响应 + 4 RST + 2 重传 + 1 正常） | 14 | packets=14、skipped_count=0，覆盖率 100% | 触发 TCP 异常规则；验证标志位与 seq |
| `nonip.pcap` | 脚本构造（ARP + 未知以太网类型） | 4 | packets=0、skipped_count=4，覆盖率 0% | 验证"非 IP 数据包"跳过逻辑 |
| `empty.pcap` | 脚本构造（0 字节） | 0 | 抛 `PcapError`："文件为空（0 字节）" | 验证空文件提示 |
| `corrupt.pcap` | 脚本构造（magic 错误 + 垃圾字节） | 0 | 抛 `PcapError`："文件格式无法识别" | 验证损坏文件提示 |

## 每份样例里埋了什么

- `normal.pcap`：TCP 三次握手（SYN / SYN-ACK / ACK）、HTTP 请求与响应、DNS 查询与成功响应、NTP 的 UDP 包、一个 ARP 包（故意用来验证跳过）、一个 IPv6 的 UDP 包（验证 IPv6 基础字段）。
- `dns_fail.pcap`：6 次 NXDOMAIN + 2 次 SERVFAIL，全部来自 `192.168.1.35`，用于让 B 的 DNS 规则稳定触发；另加 1 次成功查询作为对照，避免"整份文件全是异常"导致规则无法体现比例。
- `tcp_abnormal.pcap`：同一目的 `203.0.113.9:8080` 的 5 次 SYN 没有任何应答（连接失败线索），4 条 RST+ACK（被拒绝），2 条完全相同的重传包（同四元组、同 seq、同载荷），最后 1 条正常握手做对照。
- `nonip.pcap`：3 个 ARP 广播 + 1 个未知以太网类型帧，全部不是 IP 流量，用于证明"跳过而不是崩溃"。
- `empty.pcap` / `corrupt.pcap`：只用于验证错误提示，不参与统计。

## 使用提示

- 这些是**构造数据**，包数与内容完全确定，适合写进验收记录（"预期 vs 实际"可比对）。
- 若要补充真实抓包，请用 `sudo tcpdump -i eth0 -c 200 -w samples/real.pcap`，**不要用 `-i any`**（生成 Linux cooked capture 链路类型，当前解析器按以太网解析，会整份跳过）。
- 真实抓包不要提交到仓库，课程演示统一用本目录的构造样例。
