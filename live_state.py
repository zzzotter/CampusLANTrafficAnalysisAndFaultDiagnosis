"""消费 A 的实时包队列，并向 C 提供一致的监控状态快照。"""

from __future__ import annotations

import math
import time
from collections import deque
from collections.abc import Callable
from copy import deepcopy
from queue import Empty, Queue
from threading import Event, Lock, Thread

from analyzer import compute_trend, detect_dns_failures, detect_tcp_reset_rate
from config import (
    DNS_FAILURE_WINDOW_SECONDS,
    LIVE_MAX_ALERTS,
    LIVE_MAX_PACKET_RECORDS,
    LIVE_MAX_TREND_POINTS,
    LIVE_REFRESH_SECONDS,
    LIVE_TREND_BUCKET_SECONDS,
    LIVE_WINDOW_SECONDS,
    PROBE_INTERVAL_SECONDS,
    PROBE_TARGETS,
    PROBE_TIMEOUT_SECONDS,
    TCP_RESET_WINDOW_SECONDS,
)
from prober import probe_all


class LiveState:
    """一个队列消费者、一个定时探测线程和一份只读状态快照。"""

    def __init__(
        self,
        packet_queue: Queue,
        capture_stats: Callable[[], dict] | None = None,
        *,
        probe_targets=PROBE_TARGETS,
        probe_timeout: float = PROBE_TIMEOUT_SECONDS,
        probe_interval: float = PROBE_INTERVAL_SECONDS,
        window_seconds: float = LIVE_WINDOW_SECONDS,
        refresh_seconds: float = LIVE_REFRESH_SECONDS,
        max_packet_records: int = LIVE_MAX_PACKET_RECORDS,
    ) -> None:
        if packet_queue.maxsize < 1:
            raise ValueError("实时采集需要有界队列")
        intervals = (window_seconds, refresh_seconds, probe_timeout, probe_interval)
        if max_packet_records < 1 or any(not math.isfinite(value) or value <= 0 for value in intervals):
            raise ValueError("记录上限与时间配置必须为正数")
        self._queue = packet_queue
        self._capture_stats = capture_stats
        self._targets = tuple(deepcopy(probe_targets))
        self._probe_timeout = probe_timeout
        self._probe_interval = probe_interval
        self._window_seconds = window_seconds
        self._refresh_seconds = refresh_seconds
        self._max_packet_records = max_packet_records
        self._retention_seconds = max(window_seconds, DNS_FAILURE_WINDOW_SECONDS, TCP_RESET_WINDOW_SECONDS)
        self._stop_event = Event()
        self._state_lock = Lock()
        self._lifecycle_lock = Lock()
        self._threads: list[Thread] = []
        self._reset()

    def _reset(self) -> None:
        self._records: deque[dict] = deque(maxlen=self._max_packet_records)
        self._last_evicted_at = float("-inf")
        self._consumer_errors = 0
        self._consumer_error = None
        with self._state_lock:
            self._snapshot = {
                "source": "live",
                "updated_at": None,
                "probes": [],
                "window": {"seconds": self._window_seconds, "packets": 0, "bytes": 0, "truncated": False},
                "alerts": [],
                "trend": [],
                "queue": {"length": self._queue.qsize(), "dropped": 0, "capture_errors": 0, "last_error": None},
            }

    def start(self) -> None:
        """启动工作线程，重复启动不会再创建消费者。"""
        with self._lifecycle_lock:
            if any(thread.is_alive() for thread in self._threads):
                return
            self._reset()
            self._stop_event.clear()
            self._threads = [Thread(target=self._consume, name="live-analysis", daemon=True)]
            if self._targets:
                self._threads.append(Thread(target=self._probe, name="live-prober", daemon=True))
            for thread in self._threads:
                thread.start()

    def stop(self, timeout: float | None = None) -> bool:
        """发出停止信号，在限时内等待线程结束并返回是否均已退出。"""
        wait_seconds = self._probe_timeout + 1.0 if timeout is None else timeout
        with self._lifecycle_lock:
            self._stop_event.set()
            deadline = time.monotonic() + wait_seconds
            for thread in self._threads:
                thread.join(max(0.0, deadline - time.monotonic()))
            return not any(thread.is_alive() for thread in self._threads)

    def get_snapshot(self) -> dict:
        """C 可以随时读取独立副本，修改副本不会影响工作线程。"""
        with self._state_lock:
            return deepcopy(self._snapshot)

    def _consume(self) -> None:
        next_refresh = time.monotonic()
        while not self._stop_event.is_set():
            now = time.monotonic()
            if now >= next_refresh:
                self._publish()
                next_refresh = time.monotonic() + self._refresh_seconds
            try:
                timeout = min(0.2, max(0.0, next_refresh - time.monotonic()))
                packet = self._queue.get(timeout=timeout)
            except Empty:
                continue
            try:
                self._accept(packet)
            except (AttributeError, KeyError, TypeError, ValueError, OverflowError) as exc:
                self._consumer_errors += 1
                self._consumer_error = f"包记录无效：{exc}"
            finally:
                self._queue.task_done()
        self._publish()

    def _accept(self, packet: dict) -> None:
        if packet.get("status") == "skipped":
            return
        timestamp, length = float(packet["timestamp"]), packet["length"]
        if not math.isfinite(timestamp) or not isinstance(length, int) or length < 0:
            raise ValueError("时间戳或包长度无效")
        src, dst, protocol = packet["src_ip"], packet["dst_ip"], packet["protocol"]
        if not all(isinstance(value, str) for value in (src, dst, protocol)):
            raise ValueError("IP 和协议字段必须是字符串")
        dns = packet.get("dns")
        if dns is not None and not isinstance(dns, dict):
            raise ValueError("DNS 字段必须是字典或 None")

        if len(self._records) == self._max_packet_records:
            self._last_evicted_at = max(self._last_evicted_at, self._records[0]["timestamp"])
        self._records.append({
            "timestamp": timestamp, "length": length, "protocol": protocol,
            "src_ip": src, "dst_ip": dst, "tcp_rst": packet.get("tcp_rst"),
            "dns": {"is_response": dns.get("is_response"), "rcode": dns.get("rcode")} if dns else None,
        })

    def _publish(self) -> None:
        now = time.time()
        cutoff = now - self._retention_seconds
        self._records = deque(
            (packet for packet in self._records if packet["timestamp"] >= cutoff),
            maxlen=self._max_packet_records,
        )
        packets = [packet for packet in self._records if packet["timestamp"] <= now]
        recent = [packet for packet in packets if packet["timestamp"] >= now - self._window_seconds]
        dns_packets = [packet for packet in packets if packet["timestamp"] >= now - DNS_FAILURE_WINDOW_SECONDS]
        tcp_packets = [packet for packet in packets if packet["timestamp"] >= now - TCP_RESET_WINDOW_SECONDS]
        alerts = detect_dns_failures(dns_packets) + detect_tcp_reset_rate(tcp_packets)
        alerts.sort(key=lambda alert: alert["end_time"], reverse=True)

        trend_start = now - LIVE_TREND_BUCKET_SECONDS * (LIVE_MAX_TREND_POINTS - 1)
        trend = compute_trend(
            (packet for packet in recent if packet["timestamp"] >= trend_start),
            bucket_seconds=LIVE_TREND_BUCKET_SECONDS,
        )
        try:
            capture = self._capture_stats() if self._capture_stats else {}
        except (OSError, RuntimeError) as exc:
            capture = {"last_error": f"采集状态读取失败：{exc}"}
        queue = {
            "length": self._queue.qsize(),
            "capacity": self._queue.maxsize,
            "dropped": capture.get("dropped", 0),
            "capture_errors": capture.get("capture_errors", capture.get("convert_failed", 0)),
            "last_error": capture.get("last_error") or self._consumer_error,
            "consumer_errors": self._consumer_errors,
        }
        with self._state_lock:
            self._snapshot.update({
                "updated_at": time.time(),
                "window": {
                    "seconds": self._window_seconds,
                    "packets": len(recent),
                    "bytes": sum(packet["length"] for packet in recent),
                    "truncated": self._last_evicted_at >= now - self._window_seconds,
                },
                "alerts": alerts[:LIVE_MAX_ALERTS],
                "trend": trend,
                "queue": queue,
            })

    def _probe(self) -> None:
        while not self._stop_event.is_set():
            started = time.monotonic()
            results = probe_all(self._targets, timeout=self._probe_timeout, stop_event=self._stop_event)
            with self._state_lock:
                self._snapshot["probes"] = results
                self._snapshot["updated_at"] = time.time()
            self._stop_event.wait(max(0.0, self._probe_interval - (time.monotonic() - started)))
