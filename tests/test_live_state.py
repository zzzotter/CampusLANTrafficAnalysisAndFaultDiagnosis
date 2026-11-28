import importlib
import time
from pathlib import Path
from queue import Queue
from threading import Event

import pytest

from live_state import LiveState
from sniffer import replay


SAMPLES = Path(__file__).resolve().parents[1] / "samples"


def wait_snapshot(state, ready):
    deadline = time.monotonic() + 2.0
    while time.monotonic() < deadline:
        snapshot = state.get_snapshot()
        if ready(snapshot):
            return snapshot
        time.sleep(0.01)
    pytest.fail(f"状态未能及时更新：{state.get_snapshot()}")


def packet(timestamp, length=54):
    return {
        "timestamp": timestamp, "length": length, "protocol": "TCP",
        "src_ip": "192.168.1.20", "dst_ip": "192.168.1.1", "tcp_rst": False,
    }


@pytest.mark.parametrize(
    "sample, expected_bytes, expected_alert",
    [
        ("normal", 894, None),
        ("dns_fail", 1433, ("DNS 失败", "192.168.1.35", "failure_count", 8, 5)),
        ("tcp_abnormal", 766, ("TCP 重置率异常", "203.0.113.9", "reset_rate", 1.0, 0.5)),
    ],
)
def test_a_replay_reaches_the_existing_flask_endpoint(monkeypatch, sample, expected_bytes, expected_alert):
    web = importlib.import_module("web.app")
    monkeypatch.setattr(web, "_snapshot_provider", None)
    records, stats = replay(str(SAMPLES / f"{sample}.pcap"))
    packets = Queue(maxsize=32)
    state = LiveState(packets, stats.as_dict, probe_targets=(), refresh_seconds=0.01)
    web.set_snapshot_provider(state.get_snapshot)
    shift = time.time() - 1 - max(record["timestamp"] for record in records)
    for record in records:
        timestamp = record["timestamp"] + shift
        packets.put_nowait(dict(record, timestamp=timestamp, capture_time=timestamp))

    state.start()
    try:
        wait_snapshot(state, lambda data: data["window"]["packets"] == len(records))
        response = web.app.test_client().get("/api/state")
        assert response.status_code == 200
        snapshot = response.get_json()
        assert snapshot["source"] == "live"
        assert snapshot["updated_at"] > 0
        assert snapshot["window"]["seconds"] == 60
        assert snapshot["window"]["bytes"] == expected_bytes
        assert snapshot["queue"]["length"] == 0
        assert snapshot["queue"]["dropped"] == stats.dropped
        assert sum(point["bytes"] for point in snapshot["trend"]) == expected_bytes
        if expected_alert is None:
            assert snapshot["alerts"] == []
        else:
            alert, = snapshot["alerts"]
            kind, ip, metric, expected, threshold = expected_alert
            assert (alert["type"], alert["device_ip"], alert[metric], alert["threshold"]) == (
                kind, ip, expected, threshold,
            )
            assert alert["start_time"] <= alert["end_time"] and alert["reason"]
    finally:
        assert state.stop()


def test_idle_window_expires_even_if_an_old_packet_arrives_out_of_order():
    packets = Queue(maxsize=4)
    state = LiveState(packets, probe_targets=(), window_seconds=0.5, refresh_seconds=0.01)
    now = time.time()
    packets.put_nowait(packet(now))
    packets.put_nowait(packet(now - 1, length=100))
    state.start()
    try:
        current = wait_snapshot(state, lambda data: data["window"]["packets"] == 1)
        empty = wait_snapshot(state, lambda data: data["window"]["packets"] == 0)
        assert current["window"]["bytes"] == 54
        assert empty["window"]["bytes"] == 0
        assert empty["updated_at"] > current["updated_at"]
        assert empty["trend"] == []
    finally:
        assert state.stop()


def test_bounded_records_and_snapshot_copy_preserve_queue_statistics():
    packets = Queue(maxsize=4)
    state = LiveState(
        packets, lambda: {"dropped": 7, "convert_failed": 2, "last_error": "采集错误示例"},
        probe_targets=(), max_packet_records=2, refresh_seconds=0.01,
    )
    for item in ({}, packet(time.time()), packet(time.time()), packet(time.time())):
        packets.put_nowait(item)
    state.start()
    state.start()
    try:
        snapshot = wait_snapshot(state, lambda data: data["window"]["truncated"])
        assert snapshot["window"]["packets"] == 2
        assert snapshot["queue"] == {
            "length": 0, "capacity": 4, "dropped": 7, "capture_errors": 2,
            "last_error": "采集错误示例", "consumer_errors": 1,
        }
        snapshot["window"]["packets"] = 999
        assert state.get_snapshot()["window"]["packets"] == 2
    finally:
        assert state.stop()
        assert state.stop()


def test_alert_and_trend_caps_keep_recent_data(monkeypatch):
    monkeypatch.setattr("live_state.LIVE_MAX_ALERTS", 2)
    monkeypatch.setattr("live_state.LIVE_MAX_TREND_POINTS", 3)
    packets = Queue(maxsize=20)
    state = LiveState(packets, probe_targets=(), refresh_seconds=0.01)
    now = time.time()
    for index, seconds_ago in enumerate((6, 1.25, 0.25), start=1):
        for _ in range(5):
            packets.put_nowait(dict(
                packet(now - seconds_ago), protocol="UDP", dst_ip=f"192.168.1.{index}",
                dns={"is_response": True, "rcode": 3},
            ))
    state.start()
    try:
        snapshot = wait_snapshot(state, lambda data: data["window"]["packets"] == 15)
        assert [alert["device_ip"] for alert in snapshot["alerts"]] == ["192.168.1.3", "192.168.1.2"]
        assert 1 <= len(snapshot["trend"]) <= 3
        assert sum(point["packet_count"] for point in snapshot["trend"]) == 10
    finally:
        assert state.stop()


def test_slow_probe_does_not_block_traffic_and_failure_reaches_snapshot(monkeypatch):
    entered, release = Event(), Event()
    failed = {
        "target": "DNS 演示", "type": "dns", "status": "fail",
        "latency_ms": None, "last_probe_at": time.time(), "error": "探测超时",
    }

    def slow_probe(*_args, **_kwargs):
        entered.set()
        release.wait(2)
        return [failed]

    monkeypatch.setattr("live_state.probe_all", slow_probe)
    packets = Queue(maxsize=4)
    state = LiveState(packets, refresh_seconds=0.01)
    state.start()
    try:
        assert entered.wait(1)
        packets.put_nowait(packet(time.time()))
        snapshot = wait_snapshot(state, lambda data: data["window"]["packets"] == 1)
        assert snapshot["probes"] == []
        release.set()
        snapshot = wait_snapshot(state, lambda data: bool(data["probes"]))
        assert snapshot["probes"][0]["status"] == "fail"
        assert snapshot["window"]["packets"] == 1
    finally:
        release.set()
        assert state.stop()
