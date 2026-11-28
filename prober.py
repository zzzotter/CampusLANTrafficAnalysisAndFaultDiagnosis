"""探测单个已配置的网关、DNS 或 TCP 目标。"""

from __future__ import annotations

import ipaddress
import json
import math
import os
import re
import secrets
import socket
import struct
import subprocess
import sys
import time
from threading import Event

from scapy.error import Scapy_Exception
from scapy.layers.dns import DNS, DNSQR

from config import PROBE_TARGETS, PROBE_TIMEOUT_SECONDS


def _icmp_latency(address: str, timeout: float) -> float:
    target = ipaddress.ip_address(address)
    if os.name == "nt":
        command = ["ping", "-n", "1", "-w", str(math.ceil(timeout * 1000)), str(target)]
    else:
        executable = "ping6" if target.version == 6 and sys.platform == "darwin" else "ping"
        command = [executable, "-c", "1", str(target)]
    result = subprocess.run(
        command, capture_output=True, timeout=timeout, check=False,
        creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
    )
    # Windows 在收到“目标不可达”时也可能返回 0，收到带耗时的 Echo Reply 才算成功。
    match = re.search(rb"[=<]\s*(\d+(?:[.,]\d+)?)\s*ms\b", result.stdout)
    if result.returncode != 0 or match is None:
        raise OSError("未收到 ICMP 回应")
    return float(match[1].replace(b",", b"."))


def _remaining(deadline: float) -> float:
    remaining = deadline - time.monotonic()
    if remaining <= 0:
        raise TimeoutError
    return remaining


def _resolve_ipv4(server: str, port: int, hostname: str, deadline: float) -> str:
    server_ip = ipaddress.ip_address(server)
    family = socket.AF_INET6 if server_ip.version == 6 else socket.AF_INET
    request_id = secrets.randbits(16)
    query = DNS(id=request_id, rd=1, qd=DNSQR(qname=hostname, qtype="A"))
    with socket.socket(family, socket.SOCK_DGRAM) as sock:
        sock.settimeout(_remaining(deadline))
        sock.connect((str(server_ip), port))
        sock.send(bytes(query))
        sock.settimeout(_remaining(deadline))
        response = DNS(sock.recv(4096))
    if response.id != request_id or response.qr != 1:
        raise OSError("收到无法匹配的 DNS 响应")
    if response.tc:
        raise OSError("DNS 响应被截断")
    if response.rcode:
        raise OSError(f"DNS 返回错误码 {response.rcode}")

    answers = response.an
    # Scapy 2.5 用 payload 链表示多个应答，新版本用列表。
    for index in range(int(response.ancount or 0)):
        if isinstance(answers, list):
            record = answers[index]
        else:
            record, answers = answers, getattr(answers, "payload", None)
        if getattr(record, "type", None) == 1:
            return str(ipaddress.IPv4Address(record.rdata))
    raise OSError("DNS 响应中没有 IPv4 地址")


def probe_target(target: dict, *, timeout: float = PROBE_TIMEOUT_SECONDS) -> dict:
    """返回 C 使用的节点状态格式。失败也记录本次探测时间与耗时。"""
    kind = target.get("type", "")
    address = str(target.get("target", ""))
    name = target.get("name", kind)
    label = f"{name} {address}"
    port = target.get("port", 53 if kind == "dns" else 443)
    if kind == "tcp":
        label = f"{name} [{address}]:{port}" if ":" in address else f"{label}:{port}"
    started = time.monotonic()
    error = None
    latency = None
    try:
        if not math.isfinite(timeout) or timeout <= 0:
            raise ValueError("探测超时必须为正数")
        if kind in ("dns", "tcp"):
            port = int(port)
            if not 1 <= port <= 65535:
                raise ValueError("探测端口必须在 1 到 65535 之间")
        deadline = started + timeout
        if kind == "icmp":
            latency = _icmp_latency(address, timeout)
        elif kind == "dns":
            _resolve_ipv4(address, port, target["query"], deadline)
        elif kind == "tcp":
            try:
                ip = ipaddress.ip_address(address)
            except ValueError:
                resolver = target.get("resolver")
                if not resolver:
                    raise ValueError("TCP 域名目标需要配置 resolver 或改用 IP 地址") from None
                ip = ipaddress.ip_address(_resolve_ipv4(resolver, 53, address, deadline))
            family = socket.AF_INET6 if ip.version == 6 else socket.AF_INET
            with socket.socket(family, socket.SOCK_STREAM) as sock:
                sock.settimeout(_remaining(deadline))
                sock.connect((str(ip), port))
        else:
            raise ValueError(f"未知探测类型 {kind}")
    except (TimeoutError, subprocess.TimeoutExpired):
        error = f"探测超时（{timeout:g} 秒）"
    except (OSError, TypeError, ValueError, OverflowError, KeyError, IndexError, struct.error, Scapy_Exception) as exc:
        error = str(exc) or type(exc).__name__

    elapsed = round((time.monotonic() - started) * 1000, 2)
    return {
        "target": label,
        "type": kind,
        "status": "ok" if error is None else "fail",
        "latency_ms": (elapsed if latency is None else latency) if error is None else None,
        "elapsed_ms": elapsed,
        "last_probe_at": time.time(),
        "error": error,
    }


def probe_all(
    targets=PROBE_TARGETS, *, timeout: float = PROBE_TIMEOUT_SECONDS, stop_event: Event | None = None
) -> list[dict]:
    """执行一轮定点探测，关闭信号会跳过尚未开始的目标。"""
    results = []
    for target in targets:
        if stop_event is not None and stop_event.is_set():
            break
        results.append(probe_target(target, timeout=timeout))
    return results


if __name__ == "__main__":
    print(json.dumps(probe_all(), ensure_ascii=False, indent=2))
