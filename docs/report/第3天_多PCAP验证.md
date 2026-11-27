# 第三天（11/26）多 PCAP 验证与稳定性检查（成员 A）

生成时间：2026-11-25 18:54:42
结论：4/4 项通过，解析部分可供 50% 验收

## 检查项

| 检查项 | 结果 | 说明 |
| --- | --- | --- |
| 1. 多 PCAP 验证（7 个 pcap + 1 个 pcapng） | 通过 | 8/8 个样例结果与预期一致 |
| 2. 坏输入稳定性（截断/垃圾/目录） | 通过 | 7 个坏输入全部按约定处理，无中断、无未知异常 |
| 3. 字段冻结（7 核心 + 17 扩展，共 24 项） | 通过 | 字段名、顺序与冻结清单完全一致，可用于 50% 验收 |
| 4. 性能：万包级抓包 | 通过 | 10000 个包（1074 KB）解析用时 1402 ms，约 7,131 包/秒 |

## 多格式 / 多样例验证

| 样例 | 原始包数 | packets | skipped | 覆盖率 | 耗时(ms) | 提示 | 结论 |
| --- | --- | --- | --- | --- | --- | --- | --- |
| normal.pcap | 12 | 11 | 1 | 91.67% | 4.6 | — | 通过 |
| normal.pcapng | 12 | 11 | 1 | 91.67% | 2.8 | — | 通过 |
| dns_fail.pcap | 18 | 18 | 0 | 100.0% | 5.7 | — | 通过 |
| tcp_abnormal.pcap | 14 | 14 | 0 | 100.0% | 3.3 | — | 通过 |
| dns_malformed.pcap | 3 | 3 | 0 | 100.0% | 2.6 | — | 通过 |
| nonip.pcap | 4 | 0 | 4 | 0.0% | 2.2 | — | 通过 |
| empty.pcap | — | — | — | — | — | 文件为空（0 字节） | 通过 |
| corrupt.pcap | — | — | — | — | — | 文件格式无法识别，可能已损坏或不是 PCAP/PCAPNG 文件 | 通过 |

## 坏输入稳定性（不中断、不抛未知异常）

| 用例 | 程序行为 | 是否保留部分结果 | 结论 |
| --- | --- | --- | --- |
| 截断到 50% | 正常返回 packets=5、skipped=0 | 5 条 | 通过 |
| 截断到 90% | 正常返回 packets=10、skipped=1 | 10 条 | 通过 |
| 只剩 1 字节 | PcapError：文件格式无法识别，可能已损坏或不是 PCAP/PCAPNG 文件：/tmp/pcap_fuzz_yx3awlw4/case.pcap | 无 | 通过 |
| 头部 magic 错误 | PcapError：文件格式无法识别，可能已损坏或不是 PCAP/PCAPNG 文件：/tmp/pcap_fuzz_yx3awlw4/case.pcap | 无 | 通过 |
| 正确 magic + 垃圾数据 | 正常返回 packets=0、skipped=1 | 0 条 | 通过 |
| 空字节文件 | PcapError：文件为空（0 字节）：/tmp/pcap_fuzz_yx3awlw4/case.pcap | 无 | 通过 |
| 传入目录 | PcapError：给的是目录不是文件：/tmp/pcap_fuzz_yx3awlw4 | 无 | 通过 |

## 性能

- 10,000 个包 / 1074 KB，用时 1402 ms，约 7,131 包/秒

## 字段冻结清单（11/26 起锁定）

- 核心 7 项：timestamp, src_ip, dst_ip, src_port, dst_port, protocol, length
- 扩展 17 项：index, captured_length, payload_len, ip_version, src_mac, dst_mac, tcp_flags, tcp_syn, tcp_ack, tcp_rst, tcp_fin, tcp_seq, tcp_ack_num, tcp_window, dns, status, skip_reason

变更流程：确有需要时，先通知 B、C，再同步改 parser.py、analyzer.py、main.py 与《数据字段规范》，四者缺一不可。
