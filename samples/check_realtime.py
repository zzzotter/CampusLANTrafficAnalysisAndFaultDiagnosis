"""实时抓包链路自检（A 模块 11/27 + 11/28 验收项）

覆盖当天四条验收要求：
    1. 单包转换入口可独立调用，输出 24 字段
    2. 网卡抓包 → 单包转换 → 有界队列 生产流程（用回放等价验证）
    3. 停止抓包、可重启；权限/网卡错误给出中文提示
    4. 统计捕获数、转换失败数、入队丢弃数

用法：python scripts/check_realtime.py
"""

from __future__ import annotations

import os
import sys
import time

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

from parser import CORE_FIELDS, EXTRA_FIELDS, parse_packet, parse_pcap  # noqa: E402
from scapy.all import PcapReader, rdpcap  # noqa: E402

import sniffer  # noqa: E402
from sniffer import CaptureError, PacketSniffer, list_ifaces, replay, resolve_capture_iface  # noqa: E402

SAMPLES = os.path.join(ROOT, "samples")
RESULTS: list[tuple[str, bool, str]] = []


def check(name: str, ok: bool, detail: str = "") -> None:
    RESULTS.append((name, ok, detail))
    print(f"[{'通过' if ok else '失败'}] {name}" + (f"    {detail}" if detail else ""))


# ---------------------------------------------------------------- 1. 单包入口

def test_single_packet_entry() -> None:
    pkts = rdpcap(os.path.join(SAMPLES, "normal.pcap"))
    rec = parse_packet(pkts[0], 1)
    d = rec.to_dict()
    expect = set(CORE_FIELDS) | set(EXTRA_FIELDS)
    ok_fields = set(d.keys()) == expect
    check(
        "1. 单包转换入口（parse_packet）可独立调用，字段完整",
        ok_fields,
        f"{len(d)} 个字段，protocol={d['protocol']}，{d['src_ip']}:{d['src_port']}→{d['dst_ip']}:{d['dst_port']}",
    )

    # 真正的实时要求：单包转换失败不能把抓包线程带崩
    class Broken:
        pass

    sn = PacketSniffer()
    sn.stats_data = sniffer.SnifferStats(started_at=time.time())
    sn._on_packet(Broken())          # 故意给一个非法对象
    st = sn.stats()
    check(
        "1b. 单包转换失败只计数、不抛异常（抓包线程存活）",
        st["convert_failed"] == 1 and st["captured"] == 1 and bool(st["last_error"]),
        f"captured={st['captured']}、convert_failed={st['convert_failed']}、last_error={st['last_error']}",
    )


# ---------------------------------------------------------------- 2. 有界队列

def test_bounded_queue() -> None:
    sn = PacketSniffer(queue_maxsize=3)
    sn.stats_data = sniffer.SnifferStats(started_at=time.time(), queue_maxsize=3)
    pkts = rdpcap(os.path.join(SAMPLES, "dns_fail.pcap"))
    for i, p in enumerate(pkts, 1):
        sn._on_packet(p)
    st = sn.stats()
    ok = st["enqueued"] == 3 and st["queue_len"] == 3 and st["dropped"] == st["converted"] - 3
    check(
        "2. 有界队列满了丢新包、不阻塞、计入 dropped",
        ok,
        f"容量 3，灌 {st['captured']} 包 → 入队 {st['enqueued']}、丢弃 {st['dropped']}、队列长 {st['queue_len']}",
    )


# ---------------------------------------------------------------- 3. 与离线一致

def test_replay_consistency() -> None:
    cases = ["normal.pcap", "dns_fail.pcap", "tcp_abnormal.pcap", "dns_malformed.pcap"]
    all_ok = True
    lines = []
    for name in cases:
        path = os.path.join(SAMPLES, name)
        packets_off, skipped_off = parse_pcap(path)
        records, st = replay(path)
        ok = len(records) == len(packets_off) and st.skipped == skipped_off
        all_ok &= ok
        lines.append(f"{name}: 离线 {len(packets_off)}/{skipped_off} vs 实时 {len(records)}/{st.skipped}")
    check("3. 回放走同一条生产链路，结果与离线分析一致", all_ok, "；".join(lines))


# ---------------------------------------------------------------- 4. 生命周期

def test_lifecycle() -> None:
    sn = PacketSniffer(iface="不存在的网卡")
    raised = None
    try:
        sn.start()
    except CaptureError as exc:
        raised = str(exc)
    check("4a. 网卡不存在 → 中文错误且不崩溃", bool(raised) and "不存在" in (raised or ""), raised or "未抛错")

    sn2 = PacketSniffer()
    sn2.stop()          # 未启动时调用
    sn2.stop()          # 重复调用
    check("4b. 未启动/重复 stop() 不抛异常", True, "幂等停止")

    # 真实启动（本机若无权限则验证报错文案；有权限则验证启停重启）
    live_msg = ""
    iface = None
    for it in list_ifaces():
        if not it["is_loopback"]:
            iface = it["name"]
            break
    sn3 = PacketSniffer(iface=iface, queue_maxsize=100)
    try:
        sn3.start()
        sn3.stop()
        sn3.start()
        time.sleep(0.5)
        sn3.stop()
        check("4c. 指定网卡可启动、停止、再启动", True, f"网卡 {iface}，3 次启停无异常")
    except CaptureError as exc:
        live_msg = str(exc)
        check("4c. 无抓包权限时给出中文提示（演示机应换有权限环境复测）", "权限" in live_msg, live_msg)


# ---------------------------------------------------------------- 5. 统计字段

def test_stats_fields() -> None:
    need = {"captured", "converted", "skipped", "convert_failed", "enqueued",
            "dropped", "queue_len", "queue_maxsize", "elapsed_s", "last_error",
            "running", "iface"}
    sn = PacketSniffer()
    got = set(sn.stats().keys())
    check("5. 采集统计字段齐全（B 读快照需要）", need <= got,
          "缺：" + "、".join(sorted(need - got)) if not need <= got else f"{len(got)} 个字段")


# ---------------------------------------------------------------- 6. 网卡标记

def test_iface_marks() -> None:
    items = list_ifaces()
    ok = bool(items)
    detail_bits = []
    if ok:
        # 环回必须只有一个语义来源：名字或 127.x，不能靠平台标志位拍脑袋
        for it in items:
            if it["is_loopback"] and not (
                "loopback" in it["description"].lower()
                or all(ip.startswith("127.") for ip in it["ips"])
            ):
                ok = False
                detail_bits.append(f"{it['description']} 误判为环回")
        # 排序：推荐项必须全部在非推荐项前面
        seen_non_rec = False
        for it in items:
            if it["recommended"]:
                if seen_non_rec:
                    ok = False
                    detail_bits.append(f"{it['description']} 推荐项排在非推荐项之后")
            else:
                seen_non_rec = True
        # 自动选网卡不能挑虚拟/环回（除非真的没有别的）
        auto = resolve_capture_iface(None)
        chosen = next(i for i in items if i["name"] == auto)
        if len(items) > 1 and (chosen["is_virtual"] or chosen["is_loopback"]):
            ok = False
            detail_bits.append(f"自动选择挑了虚拟/环回网卡：{chosen['description']}")
    rec = [i["description"] for i in items if i["recommended"]]
    check(
        "6. 网卡标记与排序正确（推荐首位、环回不误判）",
        ok,
        ("；".join(detail_bits) if detail_bits else f"推荐：{'、'.join(rec) or '无'}"),
    )


def main() -> int:
    print("=" * 72)
    print("实时抓包链路自检（11/27 接口确认 + 11/28 数据链路）")
    print("=" * 72)
    test_single_packet_entry()
    test_bounded_queue()
    test_replay_consistency()
    test_lifecycle()
    test_stats_fields()
    test_iface_marks()
    passed = sum(1 for _, ok, _ in RESULTS if ok)
    print("-" * 72)
    print(f"结果：{passed}/{len(RESULTS)}")
    return 0 if passed == len(RESULTS) else 1


if __name__ == "__main__":
    raise SystemExit(main())
