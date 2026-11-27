"""命令行入口：python main.py --input samples/normal.pcap --output reports

流程：解析（parser，A） → 统计与检测（analyzer，B） → 展示与导出（reporter，C）。
解析器、统计规则、展示格式分别由三位成员维护，本文件只负责把它们串起来。
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from analyzer import (
    analyze_packets,
    compute_trend,
    detect_dns_failures,
    detect_tcp_reset_rate,
)
from parser import parse_pcap_detailed
from reporter import export_csv, export_json, print_report


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="main.py",
        description="局域网流量分析与故障诊断（PCAP 读取 → 统计 → 异常线索 → 导出）",
    )
    parser.add_argument("--input", required=True, help="PCAP/PCAPNG 文件路径")
    parser.add_argument("--output", default="reports", help="导出目录（默认 reports）")
    parser.add_argument("--format", choices=["json", "csv", "both"], default="both",
                        help="导出格式（默认 both）")
    parser.add_argument("--max-packets", type=int, default=None,
                        help="最多解析多少个包，用于大文件快速预览")
    parser.add_argument("--top", type=int, default=10, help="设备流量排行显示前 N 名")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)

    result = parse_pcap_detailed(args.input, max_packets=args.max_packets)
    if result.error:
        # 文件不存在、空文件、损坏文件：给中文提示 + 非零退出码，不打印堆栈
        print(f"[错误] {result.error}", file=sys.stderr)
        return 2

    packets = result.packets
    alerts = detect_dns_failures(packets) + detect_tcp_reset_rate(packets)
    alerts.sort(key=lambda alert: (alert["start_time"], alert["device_ip"]))

    report = {
        "source": result.source,
        "stats": result.stats.to_dict(),
        "summary": analyze_packets(packets),
        "trend": compute_trend(packets),
        "alerts": alerts,
    }

    print_report(report, top=args.top)

    stem = Path(args.input).stem
    out_dir = Path(args.output)
    written = []
    if args.format in ("json", "both"):
        written.append(export_json(report, out_dir / f"{stem}_report.json"))
    if args.format in ("csv", "both"):
        written.extend(export_csv(report, out_dir, stem=stem))

    print("\n导出文件：")
    for path in written:
        print(f"  {path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
