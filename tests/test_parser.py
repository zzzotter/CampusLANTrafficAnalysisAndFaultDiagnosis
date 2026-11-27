"""解析器的坏输入与覆盖率测试（对应 README「文件不存在、空文件、损坏文件」要求）。"""

import unittest
from pathlib import Path

from parser import PcapError, parse_pcap, parse_pcap_detailed

SAMPLES_DIR = Path(__file__).resolve().parents[1] / "samples"


class ParserErrorTests(unittest.TestCase):
    def test_missing_file_raises_pcap_error(self):
        with self.assertRaises(PcapError) as ctx:
            parse_pcap(str(SAMPLES_DIR / "不存在的文件.pcap"))
        self.assertIn("文件不存在", str(ctx.exception))

    def test_empty_file_raises_pcap_error(self):
        with self.assertRaises(PcapError) as ctx:
            parse_pcap(str(SAMPLES_DIR / "empty.pcap"))
        self.assertIn("文件为空", str(ctx.exception))

    def test_corrupt_file_raises_pcap_error(self):
        with self.assertRaises(PcapError) as ctx:
            parse_pcap(str(SAMPLES_DIR / "corrupt.pcap"))
        self.assertIn("格式无法识别", str(ctx.exception))

    def test_detailed_does_not_raise_and_keeps_error(self):
        result = parse_pcap_detailed(str(SAMPLES_DIR / "empty.pcap"))
        self.assertIsNotNone(result.error)
        self.assertEqual(result.packets, [])


class ParserCoverageTests(unittest.TestCase):
    def test_normal_capture_counts_and_coverage(self):
        result = parse_pcap_detailed(str(SAMPLES_DIR / "normal.pcap"))
        self.assertIsNone(result.error)
        self.assertEqual((result.stats.total, result.stats.skipped), (12, 1))
        self.assertEqual(len(result.packets), 11)
        self.assertEqual(result.stats.coverage, 91.67)
        # 注意：ParseStats.protocol_counts 把被跳过的 ARP 记成 OTHER，
        # 而 analyze_packets 只统计已解析的包，两处口径不同，这里不做等值断言。
        self.assertEqual(result.stats.protocol_counts["TCP"], 7)
        self.assertEqual(result.stats.protocol_counts["UDP"], 4)

    def test_pcap_and_pcapng_are_equivalent(self):
        pcap, skipped_pcap = parse_pcap(str(SAMPLES_DIR / "normal.pcap"))
        pcapng, skipped_pcapng = parse_pcap(str(SAMPLES_DIR / "normal.pcapng"))
        self.assertEqual(pcap, pcapng)
        self.assertEqual(skipped_pcap, skipped_pcapng)

    def test_nonip_capture_skips_everything(self):
        packets, skipped = parse_pcap(str(SAMPLES_DIR / "nonip.pcap"))
        self.assertEqual((len(packets), skipped), (0, 4))

    def test_malformed_dns_keeps_core_fields(self):
        result = parse_pcap_detailed(str(SAMPLES_DIR / "dns_malformed.pcap"))
        partial = [r for r in result.records if r.status == "partial"]
        self.assertEqual(len(partial), 1)
        record = partial[0].to_dict()
        self.assertTrue(record["src_ip"] and record["dst_ip"])
        self.assertIsNone(record["dns"]["query_name"])


if __name__ == "__main__":
    unittest.main()
