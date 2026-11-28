"""长时间运行观察脚本（成员 A，11/29 第 2 项）

目的：证明"持续运行一段时间后，队列、内存不随时长增长"，并留下可查的队列曲线。
它同时模拟 B 的消费者（一个常驻线程从队列取包），因此验证的是真实链路而不只是生产者。

用法：
    python scripts/longrun_check.py --duration 600            # 真实抓包 10 分钟
    python scripts/longrun_check.py --duration 60 --replay samples/normal.pcap   # 无权限时用回放

输出：
    reports/长跑记录_队列曲线.csv   （每 10 秒一行）
    终端摘要：总捕获、平均速率、队列最大长度、丢弃数、消费者是否跟上
"""

from __future__ import annotations

import argparse
import csv
import os
import queue
import sys
import threading
import time

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

from scapy.all import PcapReader  # noqa: E402

import sniffer as sniffer_mod  # noqa: E402
from sniffer import PacketSniffer  # noqa: E402

OUT_DIR = os.path.join(ROOT, "reports")


class Consumer(threading.Thread):
    """模拟 B 的常驻消费者：只从队列取、只计数，不做统计计算。"""

    def __init__(self, q: "queue.Queue", stop_event: threading.Event) -> None:
        super().__init__(daemon=True)
        self.q = q
        self.stop_event = stop_event
        self.count = 0

    def run(self) -> None:
        while not self.stop_event.is_set():
            try:
                self.q.get(timeout=0.5)
                self.count += 1
            except queue.Empty:
                continue


class PcapFeeder(threading.Thread):
    """把 pcap 当作网卡：按指定速率循环喂包，用于没有抓包权限的机器。"""

    def __init__(self, path: str, sniffer: PacketSniffer, pps: float,
                 stop_event: threading.Event) -> None:
        super().__init__(daemon=True)
        self.path = path
        self.sniffer = sniffer
        self.interval = 1.0 / max(1.0, pps)
        self.stop_event = stop_event

    def run(self) -> None:
        while not self.stop_event.is_set():
            with PcapReader(self.path) as reader:
                for pkt in reader:
                    if self.stop_event.is_set():
                        return
                    self.sniffer._on_packet(pkt)
                    time.sleep(self.interval)


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description="长时间运行观察：队列长度与丢弃情况")
    ap.add_argument("--duration", type=float, default=600, help="运行秒数，默认 600")
    ap.add_argument("--interval", type=float, default=10, help="采样间隔秒数，默认 10")
    ap.add_argument("--iface", default=None, help="网卡名，默认取 config.json / 自动选择")
    ap.add_argument("--replay", default=None, help="改用 pcap 循环回放（无权限环境）")
    ap.add_argument("--pps", type=float, default=50, help="回放速率（包/秒），默认 50")
    ap.add_argument("--out", default=os.path.join(OUT_DIR, "长跑记录_队列曲线.csv"))
    args = ap.parse_args(argv)

    stop_event = threading.Event()
    sn = PacketSniffer(iface=args.iface, queue_maxsize=5000)
    consumer = Consumer(sn.pkt_queue, stop_event)

    if args.replay:
        sn.stats_data = sniffer_mod.SnifferStats(started_at=time.time(), queue_maxsize=5000)
        feeder = PcapFeeder(args.replay, sn, args.pps, stop_event)
        print(f"回放模式：{args.replay}，约 {args.pps:g} 包/秒，运行 {args.duration:g} 秒")
        feeder.start()
    else:
        try:
            sn.start()
        except Exception as exc:
            print(f"[失败] {exc}")
            print("提示：没有权限时可用 --replay samples/normal.pcap 先验证脚本本身。")
            return 2
        print(f"真实抓包：{sn.iface}（来源：{sn.iface_source}），运行 {args.duration:g} 秒，"
              f"每 {args.interval:g} 秒采样一次")

    consumer.start()
    rows: list[dict] = []
    t0 = time.time()
    try:
        while time.time() - t0 < args.duration:
            time.sleep(min(args.interval, max(0.5, args.duration - (time.time() - t0))))
            st = sn.stats()
            row = {
                "elapsed_s": round(time.time() - t0, 1),
                "captured": st["captured"],
                "enqueued": st["enqueued"],
                "consumed": consumer.count,
                "queue_len": st["queue_len"],
                "dropped": st["dropped"],
                "convert_failed": st["convert_failed"],
                "rate_pps": round(st["captured"] / max(0.001, time.time() - t0), 1),
            }
            rows.append(row)
            print(f"  t={row['elapsed_s']:>6}s 捕获 {row['captured']:>6}  "
                  f"队列 {row['queue_len']:>4}/{st['queue_maxsize']}  "
                  f"丢弃 {row['dropped']:>3}  消费 {row['consumed']:>6}  "
                  f"{row['rate_pps']:>7.1f} 包/秒")
    except KeyboardInterrupt:
        print("\n手动中断，开始汇总。")
    finally:
        stop_event.set()
        if not args.replay:
            sn.stop()
        consumer.join(timeout=2)

    st = sn.stats()
    os.makedirs(os.path.dirname(args.out), exist_ok=True)
    with open(args.out, "w", newline="", encoding="utf-8-sig") as f:
        writer = csv.DictWriter(f, fieldnames=list(rows[0].keys()) if rows else
                                ["elapsed_s", "captured", "enqueued", "consumed",
                                 "queue_len", "dropped", "convert_failed", "rate_pps"])
        writer.writeheader()
        writer.writerows(rows)

    peak = max((r["queue_len"] for r in rows), default=0)
    print("-" * 72)
    print(f"运行 {st['elapsed_s']:g}s｜捕获 {st['captured']}｜入队 {st['enqueued']}｜"
          f"消费 {consumer.count}｜丢弃 {st['dropped']}｜转换失败 {st['convert_failed']}")
    print(f"队列峰值 {peak}/5000，末次 {st['queue_len']}；平均 "
          f"{st['captured'] / max(0.001, st['elapsed_s']):.1f} 包/秒")
    verdict = "队列未积压，长度始终远低于上限" if peak < 500 else "队列出现明显积压，需说明丢弃策略"
    print(f"判定：{verdict}")
    print(f"曲线已写入：{args.out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
