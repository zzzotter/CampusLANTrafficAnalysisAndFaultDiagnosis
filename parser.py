"""parser.py —— PCAP 读取与协议解析（成员 A）

对外契约严格遵循队长 11/24 发布的《统一数据字段约定》：

    parse_pcap(pcap_path) -> (packets, skipped_count)
        packets        : list[dict]，每个成功解析的包一条记录
        skipped_count  : int，被安全跳过的包数量

每个记录**保证**包含 7 个核心字段（顺序与约定一致）：
    timestamp(float) src_ip(str) dst_ip(str) src_port(int|None)
    dst_port(int|None) protocol(str) length(int)

在此基础上追加扩展字段（tcp 标志位、dns、payload_len 等），供 B 实现
"DNS 失败 / TCP 异常"规则使用；扩展字段缺值为 None，不改变核心字段语义。

文件级错误（不存在 / 是目录 / 空文件 / 格式损坏）通过异常 PcapError 报告，
消息为中文，C 的入口捕获后直接打印即可。
"""

from __future__ import annotations

import os
import time
from dataclasses import dataclass, field
from typing import Iterator, Optional

from scapy.all import PcapReader, Ether, IP, IPv6, TCP, UDP, DNS, ARP

#: 传输层协议归一化标签（约定要求大写）
PROTO_TCP = "TCP"
PROTO_UDP = "UDP"
PROTO_ICMP = "ICMP"
PROTO_OTHER = "OTHER"

#: 队长约定的 7 个核心字段，每条 dict 必须齐全
CORE_FIELDS = ("timestamp", "src_ip", "dst_ip", "src_port", "dst_port", "protocol", "length")

#: 扩展字段（可选使用；B 的 DNS/TCP 规则需要它们）
EXTRA_FIELDS = (
    "index", "captured_length", "payload_len", "ip_version",
    "src_mac", "dst_mac",
    "tcp_flags", "tcp_syn", "tcp_ack", "tcp_rst", "tcp_fin",
    "tcp_seq", "tcp_ack_num", "tcp_window",
    "dns", "status", "skip_reason",
)

TCP_FLAG_BITS = {"FIN": 0x01, "SYN": 0x02, "RST": 0x04, "PSH": 0x08, "ACK": 0x10, "URG": 0x20}
DNS_RCODE_NAMES = {0: "NOERROR", 1: "FORMERR", 2: "SERVFAIL", 3: "NXDOMAIN", 4: "NOTIMP", 5: "REFUSED"}


class PcapError(Exception):
    """文件级错误。消息是中文，可直接展示给用户。"""


# ---------------------------------------------------------------------------
# 1. 数据结构
# ---------------------------------------------------------------------------

@dataclass
class DnsInfo:
    """DNS 层信息。非 DNS 包为 None。"""

    txid: int
    is_response: bool
    query_name: Optional[str]
    qtype: Optional[int]
    rcode: Optional[int]
    rcode_name: Optional[str]
    answer_count: int

    def to_dict(self) -> dict:
        return {
            "txid": self.txid,
            "is_response": self.is_response,
            "query_name": self.query_name,
            "qtype": self.qtype,
            "rcode": self.rcode,
            "rcode_name": self.rcode_name,
            "answer_count": self.answer_count,
        }


@dataclass
class PacketRecord:
    """内部记录。对外只暴露 .to_dict() 的结果（list[dict]）。"""

    # --- 核心 7 字段（顺序即输出顺序） ---
    timestamp: float
    src_ip: str = ""
    dst_ip: str = ""
    src_port: Optional[int] = None
    dst_port: Optional[int] = None
    protocol: str = PROTO_OTHER
    length: int = 0

    # --- 扩展字段 ---
    index: int = 0
    captured_length: int = 0
    payload_len: int = 0
    ip_version: Optional[int] = None
    src_mac: Optional[str] = None
    dst_mac: Optional[str] = None
    tcp_flags: list[str] = field(default_factory=list)
    tcp_syn: bool = False
    tcp_ack: bool = False
    tcp_rst: bool = False
    tcp_fin: bool = False
    tcp_seq: Optional[int] = None
    tcp_ack_num: Optional[int] = None
    tcp_window: Optional[int] = None
    dns: Optional[DnsInfo] = None
    status: str = "ok"                        # ok / partial / skipped
    skip_reason: Optional[str] = None

    def to_dict(self) -> dict:
        """核心字段在前、扩展字段在后，方便 C 导出 CSV 时列顺序稳定。"""
        return {
            "timestamp": self.timestamp,
            "src_ip": self.src_ip,
            "dst_ip": self.dst_ip,
            "src_port": self.src_port,
            "dst_port": self.dst_port,
            "protocol": self.protocol,
            "length": self.length,
            "index": self.index,
            "captured_length": self.captured_length,
            "payload_len": self.payload_len,
            "ip_version": self.ip_version,
            "src_mac": self.src_mac,
            "dst_mac": self.dst_mac,
            "tcp_flags": list(self.tcp_flags),
            "tcp_syn": self.tcp_syn,
            "tcp_ack": self.tcp_ack,
            "tcp_rst": self.tcp_rst,
            "tcp_fin": self.tcp_fin,
            "tcp_seq": self.tcp_seq,
            "tcp_ack_num": self.tcp_ack_num,
            "tcp_window": self.tcp_window,
            "dns": self.dns.to_dict() if self.dns else None,
            "status": self.status,
            "skip_reason": self.skip_reason,
        }


@dataclass
class ParseStats:
    """解析统计：覆盖率、耗时、跳过原因。"""

    total: int = 0
    parsed: int = 0
    partial: int = 0
    skipped: int = 0
    total_bytes: int = 0
    elapsed_ms: float = 0.0
    protocol_counts: dict[str, int] = field(default_factory=dict)
    skip_reasons: dict[str, int] = field(default_factory=dict)

    @property
    def coverage(self) -> float:
        if self.total == 0:
            return 0.0
        return round((self.parsed + self.partial) / self.total * 100, 2)

    @property
    def packets_per_second(self) -> float:
        if self.elapsed_ms <= 0:
            return 0.0
        return round(self.total / (self.elapsed_ms / 1000.0), 1)

    def to_dict(self) -> dict:
        return {
            "total": self.total,
            "parsed": self.parsed,
            "partial": self.partial,
            "skipped": self.skipped,
            "coverage_pct": self.coverage,
            "total_bytes": self.total_bytes,
            "elapsed_ms": round(self.elapsed_ms, 1),
            "packets_per_second": self.packets_per_second,
            "protocol_counts": dict(self.protocol_counts),
            "skip_reasons": dict(self.skip_reasons),
        }


@dataclass
class ParseResult:
    """详细结果：A 自测、报告、覆盖率展示用。"""

    records: list[PacketRecord]
    stats: ParseStats
    source: str
    error: Optional[str] = None

    @property
    def packets(self) -> list[dict]:
        """按约定返回的记录列表（不含被跳过的包）。"""
        return [r.to_dict() for r in self.records if r.status != "skipped"]

    @property
    def skipped_count(self) -> int:
        return self.stats.skipped

    def to_dict(self) -> dict:
        return {
            "source": self.source,
            "error": self.error,
            "stats": self.stats.to_dict(),
            "packets": self.packets,
        }


# ---------------------------------------------------------------------------
# 2. 单包解析
# ---------------------------------------------------------------------------

def _tcp_flag_state(pkt) -> tuple[list[str], bool, bool, bool, bool]:
    value = int(pkt[TCP].flags)
    names = [n for n, bit in TCP_FLAG_BITS.items() if value & bit]
    return (
        names,
        bool(value & TCP_FLAG_BITS["SYN"]),
        bool(value & TCP_FLAG_BITS["ACK"]),
        bool(value & TCP_FLAG_BITS["RST"]),
        bool(value & TCP_FLAG_BITS["FIN"]),
    )


def _parse_dns(pkt) -> Optional[DnsInfo]:
    try:
        dns = pkt[DNS]
    except Exception:
        return None

    query_name = None
    qtype = None
    try:
        if dns.qdcount and dns.qd is not None:
            qname = dns.qd.qname
            if qname is not None:
                query_name = qname.decode("utf-8", errors="replace").rstrip(".")
            qtype = int(dns.qd.qtype) if dns.qd.qtype is not None else None
    except Exception:
        query_name = None

    is_response = bool(dns.qr)
    rcode = None
    if is_response:
        try:
            rcode = int(dns.rcode)
        except Exception:
            rcode = None

    try:
        answer_count = int(dns.ancount or 0)
    except Exception:
        answer_count = 0

    return DnsInfo(
        txid=int(getattr(dns, "id", 0) or 0),
        is_response=is_response,
        query_name=query_name,
        qtype=qtype,
        rcode=rcode,
        rcode_name=DNS_RCODE_NAMES.get(rcode) if rcode is not None else None,
        answer_count=answer_count,
    )


def parse_packet(pkt, index: int) -> PacketRecord:
    """把一个 scapy 包转成 PacketRecord。单包异常在此消化，绝不外抛。"""
    ts = float(getattr(pkt, "time", 0.0))
    cap_len = int(len(pkt))
    length = int(getattr(pkt, "wirelen", None) or cap_len)   # 约定：原始包长度

    rec = PacketRecord(
        timestamp=ts, src_ip="", dst_ip="", src_port=None, dst_port=None,
        protocol=PROTO_OTHER, length=length,
        index=index, captured_length=cap_len, payload_len=0,
    )

    if length > cap_len:
        rec.status = "partial"
        rec.skip_reason = "数据包被截断（snaplen 限制）"

    # --- 链路层 ---
    try:
        if pkt.haslayer(Ether):
            rec.src_mac = pkt[Ether].src
            rec.dst_mac = pkt[Ether].dst
    except Exception:
        pass

    # --- 网络层 ---
    try:
        if pkt.haslayer(IP):
            rec.ip_version = 4
            rec.src_ip = pkt[IP].src or ""
            rec.dst_ip = pkt[IP].dst or ""
        elif pkt.haslayer(IPv6):
            rec.ip_version = 6
            rec.src_ip = pkt[IPv6].src or ""
            rec.dst_ip = pkt[IPv6].dst or ""
        else:
            rec.status = "skipped"
            rec.skip_reason = "ARP 等非 IP 数据包" if pkt.haslayer(ARP) else "非 IP 数据包"
            return rec
    except Exception as exc:
        rec.status = "skipped"
        rec.skip_reason = f"IP 层解析失败: {type(exc).__name__}"
        return rec

    # --- 传输层 ---
    try:
        if pkt.haslayer(TCP):
            tcp = pkt[TCP]
            rec.protocol = PROTO_TCP
            rec.src_port = int(tcp.sport)
            rec.dst_port = int(tcp.dport)
            rec.tcp_seq = int(tcp.seq)
            rec.tcp_ack_num = int(tcp.ack)
            rec.tcp_window = int(getattr(tcp, "window", 0) or 0)
            names, syn, ack, rst, fin = _tcp_flag_state(pkt)
            rec.tcp_flags = names
            rec.tcp_syn, rec.tcp_ack, rec.tcp_rst, rec.tcp_fin = syn, ack, rst, fin
            rec.payload_len = len(bytes(tcp.payload))
        elif pkt.haslayer(UDP):
            udp = pkt[UDP]
            rec.protocol = PROTO_UDP
            rec.src_port = int(udp.sport)
            rec.dst_port = int(udp.dport)
            rec.payload_len = max(0, int(getattr(udp, "len", 0) or 0) - 8)
        elif rec.ip_version == 4 and int(pkt[IP].proto) == 1:
            rec.protocol = PROTO_ICMP
            rec.payload_len = max(0, length - 14 - 20)
        elif rec.ip_version == 6 and int(pkt[IPv6].nh) == 58:
            rec.protocol = PROTO_ICMP
            rec.payload_len = max(0, length - 14 - 40)
        else:
            rec.protocol = PROTO_OTHER
    except Exception as exc:
        rec.status = "partial"
        rec.skip_reason = f"传输层解析失败: {type(exc).__name__}"
        return rec

    # --- DNS：UDP/53 或 TCP/53 ---
    if rec.protocol in (PROTO_UDP, PROTO_TCP) and 53 in (rec.src_port, rec.dst_port):
        try:
            dns_info = _parse_dns(pkt)
        except Exception as exc:
            dns_info = None
            rec.status = "partial"
            rec.skip_reason = f"DNS 解析失败: {type(exc).__name__}"
        if dns_info is not None:
            rec.dns = dns_info
            # 域名取不到但包本身可读：保留基础信息，标记为部分解析
            try:
                qdcount = int(pkt[DNS].qdcount or 0)
            except Exception:
                qdcount = 0
            if qdcount and dns_info.query_name is None and rec.status == "ok":
                rec.status = "partial"
                rec.skip_reason = "DNS 域名解析失败（已保留基础包信息）"
        elif rec.status == "ok":
            rec.status = "partial"
            rec.skip_reason = "端口 53 但 DNS 解析失败"

    return rec


# ---------------------------------------------------------------------------
# 3. 文件级读取
# ---------------------------------------------------------------------------

def _iter_records(pcap_path: str) -> Iterator[PacketRecord]:
    try:
        reader = PcapReader(pcap_path)
    except FileNotFoundError:
        raise PcapError(f"文件不存在：{pcap_path}")
    except IsADirectoryError:
        raise PcapError(f"给的是目录不是文件：{pcap_path}")
    except Exception as exc:
        raise PcapError(_classify_open_error(pcap_path, exc))

    index = 0
    try:
        with reader:
            while True:
                try:
                    pkt = reader.read_packet()
                except EOFError:
                    break
                except Exception:
                    break
                if pkt is None:
                    break
                index += 1
                try:
                    yield parse_packet(pkt, index)
                except Exception:
                    yield PacketRecord(
                        timestamp=0.0, src_ip="", dst_ip="", protocol=PROTO_OTHER,
                        index=index, status="skipped", skip_reason="未知解析异常",
                    )
    except Exception:
        # 文件中途损坏：已解析的部分照常返回，不再继续读
        pass


def _classify_open_error(pcap_path: str, exc: Exception) -> str:
    msg = str(exc)
    low = msg.lower()
    if os.path.exists(pcap_path) and os.path.getsize(pcap_path) == 0:
        return f"文件为空（0 字节）：{pcap_path}"
    if any(k in low for k in ("magic", "supported capture", "unknown file format",
                              "unknown linktype", "not a supported")):
        return f"文件格式无法识别，可能已损坏或不是 PCAP/PCAPNG 文件：{pcap_path}"
    return f"文件无法读取：{pcap_path}（{msg}）"


def _analyze(pcap_path: str, max_packets: Optional[int] = None) -> ParseResult:
    """A 内部使用的详细解析：不抛异常，错误写在 result.error。"""
    stats = ParseStats()
    records: list[PacketRecord] = []
    t0 = time.perf_counter()

    if not os.path.exists(pcap_path):
        return ParseResult([], stats, pcap_path, error=f"文件不存在：{pcap_path}")
    if os.path.isdir(pcap_path):
        return ParseResult([], stats, pcap_path, error=f"给的是目录不是文件：{pcap_path}")
    if os.path.getsize(pcap_path) == 0:
        return ParseResult([], stats, pcap_path, error=f"文件为空（0 字节）：{pcap_path}")

    try:
        for rec in _iter_records(pcap_path):
            stats.total += 1
            stats.total_bytes += rec.length
            if rec.status == "ok":
                stats.parsed += 1
            elif rec.status == "partial":
                stats.partial += 1
            else:
                stats.skipped += 1
                reason = rec.skip_reason or "未说明"
                stats.skip_reasons[reason] = stats.skip_reasons.get(reason, 0) + 1
            stats.protocol_counts[rec.protocol] = stats.protocol_counts.get(rec.protocol, 0) + 1
            records.append(rec)
            if max_packets is not None and stats.total >= max_packets:
                break
    except PcapError as exc:
        stats.elapsed_ms = (time.perf_counter() - t0) * 1000
        return ParseResult(records, stats, pcap_path, error=str(exc))

    stats.elapsed_ms = (time.perf_counter() - t0) * 1000
    if stats.total == 0:
        return ParseResult(records, stats, pcap_path,
                           error=f"文件里没有可解析的数据包（可能已损坏）：{pcap_path}")
    return ParseResult(records, stats, pcap_path)


# ---------------------------------------------------------------------------
# 4. 对外接口（约定）
# ---------------------------------------------------------------------------

def parse_pcap(pcap_path: str, max_packets: Optional[int] = None) -> tuple[list[dict], int]:
    """约定入口：返回 (packets, skipped_count)。

    packets       —— list[dict]，成功解析（含"部分解析"，即核心字段可用）的包记录；
    skipped_count —— int，被安全跳过的包数量。
    文件级错误抛 PcapError（中文消息），由 C 捕获后打印。
    """
    result = _analyze(pcap_path, max_packets=max_packets)
    if result.error:
        raise PcapError(result.error)
    return result.packets, result.skipped_count


def parse_pcap_detailed(pcap_path: str, max_packets: Optional[int] = None) -> ParseResult:
    """A 自测/报告用：额外给出覆盖率、耗时、跳过原因，不抛异常。"""
    return _analyze(pcap_path, max_packets=max_packets)


def iter_packets(pcap_path: str) -> Iterator[dict]:
    """可选扩展：大文件流式读取，逐包 yield dict（字段与 parse_pcap 的记录一致）。"""
    for rec in _iter_records(pcap_path):
        if rec.status != "skipped":
            yield rec.to_dict()


def error_message(err: Exception) -> str:
    """把异常变成一句可直接展示的话，供 C 的入口使用。"""
    return str(err) if isinstance(err, PcapError) else f"解析失败：{err}"


# ---------------------------------------------------------------------------
# 5. 小工具 + 命令行自测
# ---------------------------------------------------------------------------

def format_bytes(n: int) -> str:
    if n < 1024:
        return f"{n} B"
    if n < 1024 ** 2:
        return f"{n / 1024:.1f} KB"
    if n < 1024 ** 3:
        return f"{n / 1024 ** 2:.2f} MB"
    return f"{n / 1024 ** 3:.2f} GB"


def format_ts(ts: float) -> str:
    """timestamp → 本地时间字符串，仅用于展示，不进入数据契约。"""
    return time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(ts)) if ts else ""


def _print_summary(result: ParseResult) -> None:
    if result.error:
        print(f"[错误] {result.error}")
        return
    s = result.stats
    print(f"分析文件：{result.source}")
    print(f"原始包数：{s.total:,}")
    print(f"解析覆盖率：{s.coverage}%（成功 {s.parsed:,} + 部分 {s.partial} / 共 {s.total}）")
    print(f"跳过：{s.skipped}")
    print(f"总流量：{format_bytes(s.total_bytes)}")
    print(f"解析耗时：{s.elapsed_ms:.1f} ms（{s.packets_per_second} 包/秒）")
    print("协议分布：" + "  ".join(f"{k}={v}" for k, v in sorted(s.protocol_counts.items())))
    if s.skip_reasons:
        print("跳过原因：" + "；".join(f"{k}={v}" for k, v in s.skip_reasons.items()))


if __name__ == "__main__":
    import argparse

    ap = argparse.ArgumentParser(description="PCAP 解析器自测（成员 A）")
    ap.add_argument("--input", required=True, help="PCAP/PCAPNG 文件路径")
    ap.add_argument("--max-packets", type=int, default=None, help="最多解析多少个包")
    ap.add_argument("--show", type=int, default=0, help="打印前 N 条记录（dict 形式）")
    args = ap.parse_args()

    res = parse_pcap_detailed(args.input, max_packets=args.max_packets)
    _print_summary(res)
    if not res.error:
        print(f"对外返回值：packets={len(res.packets)} 条，skipped_count={res.skipped_count}")
        for rec in res.packets[: args.show]:
            print(rec)
