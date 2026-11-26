"""核对 TCP 重置率规则的窗口、样本量和阈值边界。"""

import unittest

from analyzer import detect_tcp_reset_rate


def tcp_packet(timestamp, rst, src_ip="203.0.113.9"):
    return {
        "timestamp": float(timestamp),
        "src_ip": src_ip,
        "dst_ip": "192.168.1.35",
        "src_port": 8080,
        "dst_port": 51000,
        "protocol": "TCP",
        "length": 54,
        "tcp_rst": rst,
    }


class DetectTcpResetRateTests(unittest.TestCase):
    def test_exact_rate_sample_size_and_duration(self):
        packets = [
            tcp_packet(60, False),
            tcp_packet(15, True),
            tcp_packet(30, False),
            tcp_packet(0, True),
        ]

        alerts = detect_tcp_reset_rate(packets)
        self.assertEqual(len(alerts), 1)
        alert = alerts[0]
        self.assertEqual(alert["device_ip"], "203.0.113.9")
        self.assertEqual((alert["reset_count"], alert["tcp_count"]), (2, 4))
        self.assertEqual((alert["reset_rate"], alert["threshold"]), (0.5, 0.5))
        self.assertEqual((alert["start_time"], alert["end_time"]), (0.0, 60.0))

    def test_fewer_than_minimum_packets(self):
        self.assertEqual(detect_tcp_reset_rate([tcp_packet(t, True) for t in range(3)]), [])

    def test_expires_old_packets_and_excludes_their_rst_flags(self):
        packets = [
            tcp_packet(0, True),
            tcp_packet(20, True),
            tcp_packet(40, False),
            tcp_packet(60.001, False),
            tcp_packet(60.002, False),
        ]
        self.assertEqual(detect_tcp_reset_rate(packets), [])

    def test_window_counts_all_packets_with_the_same_timestamp(self):
        packets = [tcp_packet(0, index < 4) for index in range(10)]
        self.assertEqual(detect_tcp_reset_rate(packets), [])

    def test_devices_are_counted_separately(self):
        packets = [tcp_packet(t, True, "203.0.113.9") for t in range(2)]
        packets += [tcp_packet(t, True, "203.0.113.10") for t in range(2)]
        self.assertEqual(detect_tcp_reset_rate(packets), [])

    def test_excludes_records_without_readable_tcp_flags(self):
        packets = [tcp_packet(t, True) for t in range(3)]
        packets.append(tcp_packet(3, None))
        packets.append(tcp_packet(4, True, ""))
        packets.append(dict(tcp_packet(5, True), protocol="UDP"))
        self.assertEqual(detect_tcp_reset_rate(packets), [])

    def test_uses_adjustable_rate_threshold(self):
        packets = [tcp_packet(t, t < 2) for t in range(4)]
        self.assertEqual(detect_tcp_reset_rate(packets, rate_threshold=0.75), [])
