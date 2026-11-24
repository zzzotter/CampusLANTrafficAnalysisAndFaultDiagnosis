"""汇总 parser.parse_pcap 返回的逐包记录。

第一条告警采用 DNS 失败检测。统计带有 DNS 信息的响应包，且响应码为
非零整数。以响应包的 dst_ip 作为查询设备，缺失设备 IP 的记录不计入。
拟定按设备使用 60 秒滑动窗口，同一窗口内达到 5 条失败响应时触发。
告警记录设备 IP、时间范围、实际失败次数和阈值。规则实现时将窗口和
次数阈值放入配置，便于用正常、异常和阈值边界样例验证。
"""

from collections import Counter
from collections.abc import Iterable


def analyze_packets(packets: Iterable[dict]) -> dict:
    """返回包数、字节数、按包计的协议分布和按收发字节排序的设备排行。

    全局流量对每条记录只计一次。设备流量分别累计源 IP 的发送字节和
    目的 IP 的接收字节。空 IP 不参加设备排行。收发合计相同时按 IP 字符串排序。
    """
    total_packets = 0
    total_bytes = 0
    protocol_counts: Counter[str] = Counter()
    sent_bytes: Counter[str] = Counter()
    received_bytes: Counter[str] = Counter()

    for packet in packets:
        length = packet["length"]
        src_ip = packet["src_ip"]
        dst_ip = packet["dst_ip"]

        total_packets += 1
        total_bytes += length
        protocol_counts[packet["protocol"]] += 1

        if src_ip:
            sent_bytes[src_ip] += length
        if dst_ip:
            received_bytes[dst_ip] += length

    devices = []
    for ip in sent_bytes.keys() | received_bytes.keys():
        sent = sent_bytes[ip]
        received = received_bytes[ip]
        devices.append({
            "ip": ip,
            "sent_bytes": sent,
            "received_bytes": received,
            "total_bytes": sent + received,
        })
    devices.sort(key=lambda device: (-device["total_bytes"], device["ip"]))

    return {
        "total_packets": total_packets,
        "total_bytes": total_bytes,
        "protocol_counts": dict(protocol_counts),
        "device_ranking": devices,
    }
