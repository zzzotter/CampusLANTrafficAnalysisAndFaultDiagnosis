"""验证 DNS 告警的次数阈值、时间窗口和设备归属。"""

import unittest

from analyzer import detect_dns_failures


def dns_packet(timestamp, device_ip="192.168.1.35", *, rcode=3, is_response=True):
    return {
        "timestamp": float(timestamp),
        "src_ip": "192.168.1.53",
        "dst_ip": device_ip,
        "src_port": 53,
        "dst_port": 50192,
        "protocol": "UDP",
        "length": 77,
        "dns": {"is_response": is_response, "rcode": rcode},
    }


class DetectDnsFailuresTests(unittest.TestCase):
    def test_exact_threshold_and_window_boundary(self):
        packets = [dns_packet(timestamp) for timestamp in (60, 15, 30, 45, 0)]

        self.assertEqual(detect_dns_failures(packets[:-1]), [])
        alerts = detect_dns_failures(packets)
        self.assertEqual(len(alerts), 1)
        alert = alerts[0]
        self.assertEqual(alert["device_ip"], "192.168.1.35")
        self.assertEqual((alert["failure_count"], alert["threshold"]), (5, 5))
        self.assertEqual((alert["start_time"], alert["end_time"]), (0.0, 60.0))

    def test_failure_outside_window_does_not_count(self):
        packets = [dns_packet(timestamp) for timestamp in (0, 15, 30, 45, 60.001)]
        self.assertEqual(detect_dns_failures(packets), [])

    def test_devices_are_counted_separately(self):
        packets = [dns_packet(timestamp) for timestamp in range(4)]
        packets.append(dns_packet(4, "192.168.1.36"))
        self.assertEqual(detect_dns_failures(packets), [])

    def test_ignores_success_queries_missing_rcode_and_missing_ip(self):
        packets = [dns_packet(timestamp) for timestamp in range(4)]
        packets.append(dns_packet(4, rcode=0))
        packets.append(dns_packet(5, is_response=False))
        packets.append(dns_packet(6, rcode=None))
        packets.append(dns_packet(7, ""))
        self.assertEqual(detect_dns_failures(packets), [])
