"""结果展示与导出（C 模块）。

- print_report：把一次分析的完整结果打印到终端；
- export_json：把同一份结果整体导出为 JSON；
- export_csv：把设备排行、告警、时间趋势拆成三个 CSV。
"""

from __future__ import annotations

import csv
import json
from pathlib import Path

from parser import format_bytes, format_ts

DEVICE_COLUMNS = ["ip", "sent_bytes", "received_bytes", "total_bytes"]
ALERT_COLUMNS = ["type", "device_ip", "start_time", "end_time", "reason"]
TREND_COLUMNS = ["start_time", "packet_count", "bytes"]


def print_report(report: dict, *, top: int = 10) -> None:
    """终端报告：解析质量 → 总量 → 协议分布 → 设备排行 → 时间趋势 → 告警。"""
    stats = report["stats"]
    summary = report["summary"]

    print(f"分析文件：{report['source']}")
    print(f"原始包数：{stats['total']:,}　解析覆盖率：{stats['coverage_pct']}%"
          f"（成功 {stats['parsed']:,} + 部分 {stats['partial']}，跳过 {stats['skipped']}）")
    print(f"总流量：{format_bytes(summary['total_bytes'])}"
          f"　解析耗时：{stats['elapsed_ms']} ms")
    if stats["skip_reasons"]:
        print("跳过原因：" + "；".join(f"{k}={v}" for k, v in stats["skip_reasons"].items()))

    print("\n协议分布：")
    for protocol, count in sorted(summary["protocol_counts"].items(), key=lambda kv: -kv[1]):
        print(f"  {protocol:<6}{count:>8,} 包")

    print(f"\n设备流量排行（前 {top}）：")
    ranking = summary["device_ranking"][:top]
    if not ranking:
        print("  无可统计的 IP 设备")
    for device in ranking:
        print(f"  {device['ip']:<16}合计 {format_bytes(device['total_bytes']):>10}"
              f"　发送 {format_bytes(device['sent_bytes'])}"
              f"　接收 {format_bytes(device['received_bytes'])}")

    print(f"\n时间趋势（每个时间桶的包数/流量）：")
    for row in report["trend"]:
        print(f"  {format_ts(row['start_time'])}  {row['packet_count']:>6,} 包"
              f"  {format_bytes(row['bytes']):>10}")

    print(f"\n异常告警（{len(report['alerts'])} 条）：")
    if not report["alerts"]:
        print("  未发现异常线索")
    for alert in report["alerts"]:
        print(f"  [{alert['type']}] 设备 {alert['device_ip']}"
              f"　{format_ts(alert['start_time'])} ~ {format_ts(alert['end_time'])}")
        print(f"    依据：{alert['reason']}")


def export_json(report: dict, path: Path) -> Path:
    """整份结果导出为 JSON（UTF-8，保留中文，缩进 2）。"""
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(report, ensure_ascii=False, indent=2), encoding="utf-8")
    return path


def export_csv(report: dict, out_dir: Path, *, stem: str) -> list[Path]:
    """导出 devices / alerts / trend 三个 CSV，返回写出的文件路径。"""
    out_dir = Path(out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)

    jobs = [
        ("devices", DEVICE_COLUMNS, report["summary"]["device_ranking"]),
        ("alerts", ALERT_COLUMNS, report["alerts"]),
        ("trend", TREND_COLUMNS, report["trend"]),
    ]

    written = []
    for name, columns, rows in jobs:
        path = out_dir / f"{stem}_{name}.csv"
        # utf-8-sig：Excel 双击打开中文表头不乱码
        with path.open("w", newline="", encoding="utf-8-sig") as handle:
            writer = csv.DictWriter(handle, fieldnames=columns, extrasaction="ignore")
            writer.writeheader()
            writer.writerows(rows)
        written.append(path)
    return written
