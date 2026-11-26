"""汇总逐包记录并检测 DNS 失败和 TCP 重置异常。"""

from collections import Counter, defaultdict
from collections.abc import Iterable

from config import (
    DNS_FAILURE_THRESHOLD,
    DNS_FAILURE_WINDOW_SECONDS,
    TCP_RESET_MIN_PACKETS,
    TCP_RESET_RATE_THRESHOLD,
    TCP_RESET_WINDOW_SECONDS,
)


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


def detect_dns_failures(
    packets: Iterable[dict],
    *,
    window_seconds: float = DNS_FAILURE_WINDOW_SECONDS,
    threshold: int = DNS_FAILURE_THRESHOLD,
) -> list[dict]:
    """以 DNS 响应的目的 IP 识别设备，报告每台设备失败最多的窗口。

    首末失败的时间差小于或等于窗口长度时，这些失败属于同一个窗口。
    返回时间为 Unix 秒数。失败次数相同时选较早的窗口。
    """
    if window_seconds <= 0 or threshold < 1:
        raise ValueError("窗口长度和失败次数阈值必须大于零")

    failures_by_device: dict[str, list[float]] = defaultdict(list)
    for packet in packets:
        dns = packet.get("dns")
        device_ip = packet.get("dst_ip")
        if dns and device_ip and dns.get("is_response") and dns.get("rcode") not in (None, 0):
            failures_by_device[device_ip].append(packet["timestamp"])

    alerts = []
    for device_ip, timestamps in sorted(failures_by_device.items()):
        timestamps.sort()
        left = 0
        peak_count = 0
        peak_start = peak_end = timestamps[0]
        for right, timestamp in enumerate(timestamps):
            while timestamp - timestamps[left] > window_seconds:
                left += 1
            count = right - left + 1
            if count > peak_count:
                peak_count = count
                peak_start = timestamps[left]
                peak_end = timestamp

        if peak_count >= threshold:
            alerts.append({
                "type": "DNS 失败",
                "device_ip": device_ip,
                "start_time": peak_start,
                "end_time": peak_end,
                "failure_count": peak_count,
                "window_seconds": window_seconds,
                "threshold": threshold,
                "reason": f"{window_seconds:g} 秒内收到 {peak_count} 次 DNS 失败响应，阈值为 {threshold} 次",
            })
    return alerts


def detect_tcp_reset_rate(
    packets: Iterable[dict],
    *,
    window_seconds: float = TCP_RESET_WINDOW_SECONDS,
    rate_threshold: float = TCP_RESET_RATE_THRESHOLD,
    min_packets: int = TCP_RESET_MIN_PACKETS,
) -> list[dict]:
    """按 TCP 发送方检测 RST 占比，报告每个 IP 重置率最高的窗口。

    TCP 标志位可读的包才进入分母。相同重置率优先选包数更多的窗口，
    包数也相同时选较早的窗口。返回的开始和结束时间为 Unix 秒数。
    """
    if window_seconds <= 0 or min_packets < 1 or not 0 < rate_threshold <= 1:
        raise ValueError("窗口长度和最小包数必须大于零，重置率阈值必须大于零且不超过 1")

    tcp_by_device: dict[str, list[tuple[float, bool]]] = defaultdict(list)
    for packet in packets:
        device_ip = packet.get("src_ip")
        rst = packet.get("tcp_rst")
        if packet.get("protocol") == "TCP" and device_ip and isinstance(rst, bool):
            tcp_by_device[device_ip].append((packet["timestamp"], rst))

    alerts = []
    for device_ip, records in sorted(tcp_by_device.items()):
        records.sort(key=lambda record: record[0])
        left = 0
        reset_count = 0
        best_reset_rate = 0.0
        best_tcp_count = 0
        best_reset_count = 0
        best_start = best_end = records[0][0]

        for right, (timestamp, rst) in enumerate(records):
            reset_count += int(rst)
            while timestamp - records[left][0] > window_seconds:
                reset_count -= int(records[left][1])
                left += 1

            # 同一时间戳上的包都属于这个窗口，收齐后再计算重置率。
            if right + 1 < len(records) and records[right + 1][0] == timestamp:
                continue
            tcp_count = right - left + 1
            if tcp_count < min_packets:
                continue
            reset_rate = reset_count / tcp_count
            if (reset_rate, tcp_count) > (best_reset_rate, best_tcp_count):
                best_reset_rate = reset_rate
                best_tcp_count = tcp_count
                best_reset_count = reset_count
                best_start = records[left][0]
                best_end = timestamp

        if best_reset_rate >= rate_threshold:
            alerts.append({
                "type": "TCP 重置率异常",
                "device_ip": device_ip,
                "start_time": best_start,
                "end_time": best_end,
                "window_seconds": window_seconds,
                "reset_count": best_reset_count,
                "tcp_count": best_tcp_count,
                "reset_rate": best_reset_rate,
                "threshold": rate_threshold,
                "min_packets": min_packets,
                "reason": (
                    f"{window_seconds:g} 秒内发出的 {best_tcp_count} 个 TCP 包中 "
                    f"{best_reset_count} 个带 RST 标志，重置率 {best_reset_rate:.1%}，"
                    f"阈值 {rate_threshold:.1%}，最少 {min_packets} 个 TCP 包"
                ),
            })
    return alerts
