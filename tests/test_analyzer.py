"""用手工构造的逐包记录验证基础流量统计。"""

import unittest

from analyzer import analyze_packets


def make_packet(index, src_ip, dst_ip, protocol, length, src_port=None, dst_port=None):
    return {
        "timestamp": 1795511800.0 + index,
        "src_ip": src_ip,
        "dst_ip": dst_ip,
        "src_port": src_port,
        "dst_port": dst_port,
        "protocol": protocol,
        "length": length,
    }


class AnalyzePacketsTests(unittest.TestCase):
    def test_ten_handcrafted_packets(self):
        client = "192.168.1.10"
        web_server = "192.168.1.20"
        second_client = "192.168.1.30"
        dns_server = "192.168.1.53"
        packets = [
            make_packet(1, client, web_server, "TCP", 60, 51000, 80),
            make_packet(2, web_server, client, "TCP", 62, 80, 51000),
            make_packet(3, client, dns_server, "UDP", 74, 53000, 53),
            make_packet(4, dns_server, client, "UDP", 90, 53, 53000),
            make_packet(5, second_client, web_server, "TCP", 100, 51001, 80),
            make_packet(6, web_server, second_client, "TCP", 110, 80, 51001),
            make_packet(7, second_client, dns_server, "UDP", 70, 53001, 53),
            make_packet(8, dns_server, second_client, "UDP", 92, 53, 53001),
            make_packet(9, client, second_client, "ICMP", 98),
            make_packet(10, "", web_server, "OTHER", 50),
        ]

        summary = analyze_packets(packets)

        self.assertEqual(summary["total_packets"], 10)
        self.assertEqual(summary["total_bytes"], 806)
        self.assertEqual(summary["protocol_counts"], {"TCP": 4, "UDP": 4, "ICMP": 1, "OTHER": 1})
        self.assertEqual(summary["device_ranking"], [
            {"ip": second_client, "sent_bytes": 170, "received_bytes": 300, "total_bytes": 470},
            {"ip": client, "sent_bytes": 232, "received_bytes": 152, "total_bytes": 384},
            {"ip": web_server, "sent_bytes": 172, "received_bytes": 210, "total_bytes": 382},
            {"ip": dns_server, "sent_bytes": 182, "received_bytes": 144, "total_bytes": 326},
        ])

    def test_empty_input(self):
        self.assertEqual(analyze_packets([]), {
            "total_packets": 0,
            "total_bytes": 0,
            "protocol_counts": {},
            "device_ranking": [],
        })
