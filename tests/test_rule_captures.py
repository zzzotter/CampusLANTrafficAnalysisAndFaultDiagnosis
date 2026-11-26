"""用成员 A 的三个抓包样例验证解析、基础统计和两条检测规则。"""

import unittest
from pathlib import Path

from analyzer import analyze_packets, detect_dns_failures, detect_tcp_reset_rate
from parser import parse_pcap


SAMPLES_DIR = Path(__file__).resolve().parents[1] / "samples"


class RuleCaptureTests(unittest.TestCase):
    def test_normal_capture_preserves_baseline_and_has_no_alerts(self):
        packets, skipped = parse_pcap(str(SAMPLES_DIR / "normal.pcap"))
        stats = analyze_packets(packets)
        self.assertEqual((stats["total_packets"], skipped, stats["total_bytes"]), (11, 1, 894))
        self.assertEqual(stats["protocol_counts"], {"TCP": 7, "UDP": 4})
        self.assertEqual(stats["device_ranking"][0]["ip"], "192.168.1.20")
        self.assertEqual(stats["device_ranking"][0]["total_bytes"], 828)
        self.assertEqual(detect_dns_failures(packets), [])
        self.assertEqual(detect_tcp_reset_rate(packets), [])

    def test_dns_failure_capture(self):
        packets, skipped = parse_pcap(str(SAMPLES_DIR / "dns_fail.pcap"))
        self.assertEqual((len(packets), skipped), (18, 0))
        alerts = detect_dns_failures(packets)
        self.assertEqual(len(alerts), 1)
        self.assertEqual(alerts[0]["device_ip"], "192.168.1.35")
        self.assertEqual((alerts[0]["failure_count"], alerts[0]["threshold"]), (8, 5))
        self.assertEqual(detect_tcp_reset_rate(packets), [])

    def test_tcp_reset_capture(self):
        packets, skipped = parse_pcap(str(SAMPLES_DIR / "tcp_abnormal.pcap"))
        self.assertEqual((len(packets), skipped), (14, 0))
        self.assertEqual(detect_dns_failures(packets), [])
        alerts = detect_tcp_reset_rate(packets)
        self.assertEqual(len(alerts), 1)
        alert = alerts[0]
        self.assertEqual(alert["device_ip"], "203.0.113.9")
        self.assertEqual((alert["reset_count"], alert["tcp_count"]), (4, 4))
        self.assertEqual((alert["reset_rate"], alert["threshold"], alert["min_packets"]), (1.0, 0.5, 4))
