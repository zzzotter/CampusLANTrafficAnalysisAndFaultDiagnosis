"""生成 A 模块的测试抓包（可重复运行，不依赖真实抓包环境）。

用法：python scripts/gen_samples.py
产出：
    normal.pcap        正常混合流量（TCP 握手 + HTTP + DNS 成功 + UDP + ARP + IPv6）
    normal.pcapng      与 normal.pcap 同内容的 PCAPNG 格式（验证两种格式都能读）
    dns_fail.pcap      8 次 DNS 失败响应（NXDOMAIN / SERVFAIL），用于触发 B 的 DNS 规则
    tcp_abnormal.pcap  SYN 无响应、RST 拒绝、重传，用于触发 B 的 TCP 规则
    dns_malformed.pcap DNS 报文损坏（域名被截断），验证"解析失败保留基础信息"
    nonip.pcap         只有 ARP，用于测"非 IP 数据包跳过"
    empty.pcap         0 字节空文件
    corrupt.pcap       头部损坏、无法识别格式的文件
"""

import os
import struct
import sys

from scapy.all import (
    Ether, IP, IPv6, TCP, UDP, DNS, DNSQR, DNSRR, ARP, Raw, wrpcap,
)

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from pcap_to_pcapng import convert  # noqa: E402  同目录工具，用于派生 pcapng

# 样例固定写到仓库的 samples/ 目录，而不是脚本所在目录
OUT = str(os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "samples"))
os.makedirs(OUT, exist_ok=True)

HOST = "192.168.1.20"      # 客户端
HOST_B = "192.168.1.35"    # 另一个客户端（DNS 异常设备）
SERVER = "192.168.1.1"     # 网关 / DNS 服务器
WEB = "93.184.216.34"      # 外网 Web 服务器
DNS_SERVER = "114.114.114.114"


def eth(ip_src, ip_dst, proto_pkt, sport=None, dport=None):
    return Ether(src="aa:bb:cc:dd:ee:01", dst="aa:bb:cc:dd:ee:02") / IP(src=ip_src, dst=ip_dst) / proto_pkt


def dns_query(qname, txid, src=HOST):
    return eth(src, DNS_SERVER, UDP(sport=50000 + (txid % 1000), dport=53) /
               DNS(id=txid, qr=0, qdcount=1, qd=DNSQR(qname=qname)))


def dns_response(qname, txid, rcode=0, src=HOST, answer_ip="93.184.216.34"):
    dns = DNS(id=txid, qr=1, qdcount=1, qd=DNSQR(qname=qname), rcode=rcode)
    if rcode == 0:
        dns.ancount = 1
        dns.an = DNSRR(rrname=qname, type="A", ttl=300, rdata=answer_ip)
    return eth(DNS_SERVER, src, UDP(sport=53, dport=50000 + (txid % 1000)) / dns)


# --------------------------------------------------------------------------
# 1) normal.pcap
# --------------------------------------------------------------------------
def build_normal():
    pkts = []
    # TCP 三次握手
    pkts.append(eth(HOST, WEB, TCP(sport=49152, dport=80, flags="S", seq=1000)))
    pkts.append(eth(WEB, HOST, TCP(sport=80, dport=49152, flags="SA", seq=5000, ack=1001)))
    pkts.append(eth(HOST, WEB, TCP(sport=49152, dport=80, flags="A", seq=1001, ack=5001)))
    # HTTP 请求 / 响应
    pkts.append(eth(HOST, WEB, TCP(sport=49152, dport=80, flags="PA", seq=1001, ack=5001) /
                   Raw(load=b"GET /index.html HTTP/1.1\r\nHost: example.com\r\n\r\n")))
    pkts.append(eth(WEB, HOST, TCP(sport=80, dport=49152, flags="PA", seq=5001, ack=1024) /
                   Raw(load=b"HTTP/1.1 200 OK\r\nContent-Length: 120\r\n\r\n" + b"x" * 120)))
    pkts.append(eth(HOST, WEB, TCP(sport=49152, dport=80, flags="FA", seq=1024, ack=5121)))
    pkts.append(eth(WEB, HOST, TCP(sport=80, dport=49152, flags="FA", seq=5121, ack=1025)))
    # DNS 成功
    pkts.append(dns_query("www.example.com", 0x1234))
    pkts.append(dns_response("www.example.com", 0x1234, rcode=0))
    # 普通 UDP（NTP）
    pkts.append(eth(HOST, "192.168.1.2", UDP(sport=123, dport=123) / Raw(load=b"\x00" * 20)))
    # ARP（应被跳过）
    pkts.append(Ether(src="aa:bb:cc:dd:ee:01", dst="ff:ff:ff:ff:ff:ff", type=0x0806) /
                ARP(op=1, psrc=HOST, pdst="192.168.1.1"))
    # IPv6 基础
    pkts.append(Ether(src="aa:bb:cc:dd:ee:01", dst="aa:bb:cc:dd:ee:02", type=0x86dd) /
                IPv6(src="fe80::1", dst="fe80::2") / UDP(sport=5353, dport=5353) / Raw(load=b"mdns"))
    path = os.path.join(OUT, "normal.pcap")
    wrpcap(path, pkts)

    # 同一批包再写一份 PCAPNG，用于验证"两种格式都能读"。
    # 从刚写出的 pcap 派生，而不是用 PcapNgWriter 再写一遍：两种写入器是独立代码路径，
    # 分别写会让时间戳出现偏差，而样例声明"两种格式内容完全相同"。
    ng_path = os.path.join(OUT, "normal.pcapng")
    convert(path, ng_path)
    return path, len(pkts)


# --------------------------------------------------------------------------
# 2) dns_fail.pcap
# --------------------------------------------------------------------------
def build_dns_fail():
    pkts = []
    domains = [f"bad-{i}.example.org" for i in range(6)]
    for i, d in enumerate(domains):
        txid = 0x2000 + i
        pkts.append(dns_query(d, txid, src=HOST_B))
        pkts.append(dns_response(d, txid, rcode=3, src=HOST_B))   # NXDOMAIN
    # 再加 2 次 SERVFAIL
    for i in range(2):
        txid = 0x2100 + i
        pkts.append(dns_query(f"servfail-{i}.example.net", txid, src=HOST_B))
        pkts.append(dns_response(f"servfail-{i}.example.net", txid, rcode=2, src=HOST_B))
    # 一条正常 DNS，避免整份文件"全是异常"
    pkts.append(dns_query("www.example.com", 0x2345, src=HOST))
    pkts.append(dns_response("www.example.com", 0x2345, rcode=0, src=HOST))
    path = os.path.join(OUT, "dns_fail.pcap")
    wrpcap(path, pkts)
    return path, len(pkts)


# --------------------------------------------------------------------------
# 3) tcp_abnormal.pcap
# --------------------------------------------------------------------------
def build_tcp_abnormal():
    pkts = []
    # 5 次 SYN 无任何响应（连接超时线索）
    for i in range(5):
        pkts.append(eth(HOST_B, "203.0.113.9", TCP(sport=40000 + i, dport=8080, flags="S", seq=1000 + i)))
    # 4 次 RST 拒绝
    for i in range(4):
        pkts.append(eth("203.0.113.9", HOST_B, TCP(sport=8080, dport=40000 + i, flags="RA", seq=0, ack=1001 + i)))
    # 2 次重传（同 seq、同 ack、同端口）
    pkts.append(eth(HOST, WEB, TCP(sport=50000, dport=80, flags="PA", seq=7000, ack=9000) / Raw(load=b"hello")))
    pkts.append(eth(HOST, WEB, TCP(sport=50000, dport=80, flags="PA", seq=7000, ack=9000) / Raw(load=b"hello")))
    # 一条正常连接做对照
    pkts.append(eth(HOST, WEB, TCP(sport=51000, dport=443, flags="S", seq=1)))
    pkts.append(eth(WEB, HOST, TCP(sport=443, dport=51000, flags="SA", seq=2, ack=2)))
    pkts.append(eth(HOST, WEB, TCP(sport=51000, dport=443, flags="A", seq=2, ack=3)))
    path = os.path.join(OUT, "tcp_abnormal.pcap")
    wrpcap(path, pkts)
    return path, len(pkts)


# --------------------------------------------------------------------------
# 3.5) dns_malformed.pcap —— DNS 报文损坏，但 IP/UDP 基础信息完整
# --------------------------------------------------------------------------
def build_dns_malformed():
    """3 个包：1 个正常查询、1 个问题区被截断的查询、1 个正常响应。

    损坏包在 DNS 头里声明 qdcount=1，但问题区只有 2 字节（名字被截断），
    scapy 解析域名时必然失败。期望结果：src_ip/dst_ip/端口/protocol/length 仍然完整，
    dns.query_name 为 None，status="partial"。
    """
    def raw_query(load, src="192.168.1.40"):
        return eth(src, DNS_SERVER, UDP(sport=51000, dport=53) / Raw(load=load))

    hdr = struct.pack(">HHHHHH", 0x3000, 0x0100, 1, 0, 0, 0)   # id / flags / qdcount / ...
    pkts = [
        dns_query("www.example.com", 0x3456, src="192.168.1.40"),
        raw_query(hdr + b"\x04ab"),                            # 截断的域名
        dns_response("www.example.com", 0x3456, rcode=0, src="192.168.1.40"),
    ]
    path = os.path.join(OUT, "dns_malformed.pcap")
    wrpcap(path, pkts)
    return path, len(pkts)


# --------------------------------------------------------------------------
# 4) nonip.pcap / empty.pcap / corrupt.pcap
# --------------------------------------------------------------------------
def build_nonip():
    pkts = []
    for i in range(3):
        pkts.append(Ether(src="aa:bb:cc:dd:ee:01", dst="ff:ff:ff:ff:ff:ff", type=0x0806) /
                    ARP(op=1, psrc=f"192.168.1.{10 + i}", pdst="192.168.1.1"))
    # 一条 STP 类的未知以太网类型，验证"非 IP"分支
    pkts.append(Ether(src="aa:bb:cc:dd:ee:03", dst="01:80:c2:00:00:00", type=0x0026) / Raw(load=b"\x00" * 20))
    path = os.path.join(OUT, "nonip.pcap")
    wrpcap(path, pkts)
    return path, len(pkts)


def build_empty():
    path = os.path.join(OUT, "empty.pcap")
    open(path, "wb").close()
    return path, 0


def build_corrupt():
    path = os.path.join(OUT, "corrupt.pcap")
    with open(path, "wb") as f:
        # 故意写错 magic（真实 PCAP 是 d4 c3 b2 a1），并塞入随机字节
        f.write(struct.pack("<I", 0xDEADBEEF) + b"\x00\x01\x02\x03" + b"garbage" * 8)
    return path, 0


if __name__ == "__main__":
    made = []
    made.append(("normal.pcap", *build_normal()))
    ng = os.path.join(OUT, "normal.pcapng")
    if os.path.exists(ng):
        made.append(("normal.pcapng", ng, 12))
    made.append(("dns_fail.pcap", *build_dns_fail()))
    made.append(("tcp_abnormal.pcap", *build_tcp_abnormal()))
    made.append(("dns_malformed.pcap", *build_dns_malformed()))
    made.append(("nonip.pcap", *build_nonip()))
    made.append(("empty.pcap", *build_empty()))
    made.append(("corrupt.pcap", *build_corrupt()))

    print("生成的测试抓包：")
    print(f"{'文件':<20}{'预期包数':<10}{'大小(字节)'}")
    for name, path, count in made:
        print(f"{name:<20}{count:<10}{os.path.getsize(path)}")
