import socket
from subprocess import CompletedProcess
from threading import Thread

from scapy.layers.dns import DNS, DNSRR

from prober import probe_target


def test_gateway_distinguishes_reply_from_host_unreachable(monkeypatch):
    target = {"name": "网关", "type": "icmp", "target": "127.0.0.1"}
    monkeypatch.setattr("prober.subprocess.run", lambda *_a, **_kw:
                        CompletedProcess("ping", 0, b"Reply from 127.0.0.1: time<1ms TTL=128", b""))
    assert probe_target(target)["status"] == "ok"

    monkeypatch.setattr("prober.subprocess.run", lambda *_a, **_kw:
                        CompletedProcess("ping", 0, b"Reply from 127.0.0.1: Destination host unreachable.", b""))
    result = probe_target(target)
    assert result["status"] == "fail"
    assert result["error"] == "未收到 ICMP 回应"
    assert result["latency_ms"] is None


def test_dns_reads_a_response_and_reports_a_real_timeout():
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as server:
        server.bind(("127.0.0.1", 0))
        server.settimeout(1)
        target = {
            "name": "DNS", "type": "dns", "target": "127.0.0.1",
            "port": server.getsockname()[1], "query": "example.com",
        }

        def reply_once():
            data, sender = server.recvfrom(4096)
            query = DNS(data)
            answer = DNSRR(rrname="example.com.", type="A", rdata="192.0.2.10")
            response = DNS(id=query.id, qr=1, qd=query.qd, an=answer)
            server.sendto(bytes(response), sender)

        worker = Thread(target=reply_once, daemon=True)
        worker.start()
        try:
            result = probe_target(target, timeout=0.5)
        finally:
            worker.join(1)
        assert result["status"] == "ok"
        assert result["latency_ms"] >= 0
        assert result["last_probe_at"] > 0

        result = probe_target(target, timeout=0.05)
        assert result["status"] == "fail"
        assert "超时" in result["error"]
        assert result["elapsed_ms"] >= 0


def test_tcp_reports_reachable_and_refused_local_targets():
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server:
        server.bind(("127.0.0.1", 0))
        target = {
            "name": "外网", "type": "tcp", "target": "127.0.0.1",
            "port": server.getsockname()[1],
        }
        refused = probe_target(target, timeout=0.2)
        assert refused["status"] == "fail" and refused["error"]

        server.listen()
        result = probe_target(target, timeout=0.2)
        assert result["status"] == "ok"
        assert result["latency_ms"] >= 0


def test_invalid_probe_configuration_becomes_a_failed_result():
    target = {"name": "外网", "type": "tcp", "target": "127.0.0.1", "port": "bad"}
    result = probe_target(target)
    assert result["status"] == "fail" and result["error"]
