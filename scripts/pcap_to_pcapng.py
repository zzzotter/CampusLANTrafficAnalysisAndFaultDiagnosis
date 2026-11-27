"""把 PCAP 转成同内容的 PCAPNG（同包、同时间戳、微秒精度）。

为什么需要它：样例要求 `normal.pcap` 与 `normal.pcapng` 解析出的记录逐字段相同。
scapy 的 `wrpcap` 与 `PcapNgWriter` 是两条独立代码路径，分别写容易在时间戳上产生
偏差（仓库里就出现过 pcapng 比 pcap 早/晚一天的情况）。从 pcap 派生 pcapng，
只有一份数据来源，两种格式必然一致。

用法：
    python scripts/pcap_to_pcapng.py samples/normal.pcap samples/normal.pcapng
"""

from __future__ import annotations

import struct
import sys
from pathlib import Path

# PCAP 全局头 magic → (字节序, 时间戳小数部分的分辨率指数)
PCAP_MAGICS = {
    b"\xd4\xc3\xb2\xa1": ("<", 6),   # 小端，微秒
    b"\xa1\xb2\xc3\xd4": (">", 6),   # 大端，微秒
    b"\x4d\x3c\xb2\xa1": ("<", 9),   # 小端，纳秒
    b"\xa1\xb2\x3c\x4d": (">", 9),   # 大端，纳秒
}

BT_SHB = 0x0A0D0D0A   # Section Header Block
BT_IDB = 0x00000001   # Interface Description Block
BT_EPB = 0x00000006   # Enhanced Packet Block
BYTE_ORDER_MAGIC = 0x1A2B3C4D


def _pad4(data: bytes) -> bytes:
    return data + b"\x00" * ((4 - len(data) % 4) % 4)


def _block(block_type: int, body: bytes) -> bytes:
    """PCAPNG 块：类型(4) + 总长(4) + 内容(4 字节对齐) + 总长(4)。"""
    total = 12 + len(_pad4(body))
    return struct.pack("<II", block_type, total) + _pad4(body) + struct.pack("<I", total)


def read_pcap(path: str | Path) -> tuple[int, list[dict]]:
    """读 PCAP，返回 (链路类型, 包列表)。每个包保留微秒精度的整数刻度，避免浮点误差。"""
    raw = Path(path).read_bytes()
    magic = raw[:4]
    if magic not in PCAP_MAGICS:
        raise ValueError(f"不是受支持的 PCAP 文件：{magic!r}")
    endian, resol_exp = PCAP_MAGICS[magic]
    linktype = struct.unpack(endian + "I", raw[20:24])[0]

    packets = []
    offset = 24
    while offset + 16 <= len(raw):
        ts_sec, ts_frac, incl_len, orig_len = struct.unpack(
            endian + "IIII", raw[offset:offset + 16])
        data = raw[offset + 16:offset + 16 + incl_len]
        if len(data) < incl_len:
            break
        # 纳秒源统一折算成微秒刻度
        us = ts_frac if resol_exp == 6 else ts_frac // 1000
        packets.append({
            "ticks_us": ts_sec * 1_000_000 + us,
            "captured_len": incl_len,
            "original_len": orig_len,
            "data": data,
        })
        offset += 16 + incl_len
    return linktype, packets


def write_pcapng(path: str | Path, linktype: int, packets: list[dict],
                 snaplen: int = 65535) -> int:
    """写出 PCAPNG（微秒精度），返回写入的包数。"""
    out = bytearray()
    out += _block(BT_SHB, struct.pack("<IHHq", BYTE_ORDER_MAGIC, 1, 0, -1))

    idb = struct.pack("<HHI", linktype, 0, snaplen)
    idb += struct.pack("<HH", 9, 1) + _pad4(b"\x06")   # if_tsresol = 6 → 微秒
    idb += struct.pack("<HH", 0, 0)                    # 选项结束
    out += _block(BT_IDB, idb)

    for packet in packets:
        ticks = packet["ticks_us"]
        epb = struct.pack(
            "<IIIII", 0, ticks >> 32, ticks & 0xFFFFFFFF,
            packet["captured_len"], packet["original_len"],
        ) + _pad4(packet["data"])
        out += _block(BT_EPB, epb)

    Path(path).write_bytes(bytes(out))
    return len(packets)


def convert(src: str | Path, dst: str | Path) -> int:
    linktype, packets = read_pcap(src)
    return write_pcapng(dst, linktype, packets)


if __name__ == "__main__":
    if len(sys.argv) != 3:
        print("用法：python scripts/pcap_to_pcapng.py <输入.pcap> <输出.pcapng>")
        raise SystemExit(2)
    count = convert(sys.argv[1], sys.argv[2])
    print(f"已转换：{sys.argv[1]} → {sys.argv[2]}，{count} 个包（微秒精度，时间戳保持不变）")
