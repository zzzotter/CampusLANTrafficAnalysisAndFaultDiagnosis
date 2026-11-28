"""实时抓包模块（成员 A：采集与解析）

职责边界（按 11/27—11/30 分工文档）：
    网卡选择 → 实时捕获 → 单包转换 → 写入有界队列
只做生产，不做统计、不做告警、不做页面——那是 B 和 C 的事。

对外接口（B 只需要这几样）：
    sniffer = PacketSniffer(iface="以太网")       # 指定网卡
    sniffer.start()                                # 开始抓包
    rec = sniffer.pkt_queue.get(timeout=1)         # B 的消费者从这里取 dict
    st  = sniffer.stats()                          # 采集侧计数快照
    sniffer.stop()                                 # 停止，线程可退出
    list_ifaces()                                  # 网卡列表（给 C 做下拉框）
    check_capture_env()                            # 启动前环境自检

队列策略：有界队列（默认 5000），满了丢**新**包并累加 dropped，
          绝不阻塞抓包线程、绝不无限增长内存。

单包原则：一个包转换失败只记录错误并继续，抓包线程不会因此退出。
"""

from __future__ import annotations

import argparse
import json
import os
import queue
import sys
import threading
import time
from dataclasses import dataclass, field
from typing import Callable, Iterable, Optional

try:
    from scapy.all import AsyncSniffer, PcapReader, conf, get_if_list
    from scapy.interfaces import resolve_iface
except ImportError as exc:  # pragma: no cover
    raise SystemExit("未安装 scapy，请先执行：pip install scapy>=2.5") from exc

from parser import PacketRecord, format_ts, parse_packet

__version__ = "1.3"          # 改动后必须同步递增，命令行会打印出来
DEFAULT_QUEUE_MAXSIZE = 5000
CONFIG_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "config.json")
CONFIG_KEYS = ("iface", "queue_maxsize", "bpf")


def load_config(path: Optional[str] = None) -> dict:
    """读 config.json 的 capture 段；文件不存在/写坏都返回空配置，不阻断启动。

    优先级：命令行参数 > 环境变量 SNIFFER_IFACE > config.json > 自动选网卡
    """
    path = path or CONFIG_PATH
    if not os.path.exists(path):
        return {}
    try:
        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)
    except Exception as exc:
        print(f"[提示] 配置文件 {path} 读取失败（{exc}），改用默认设置。", file=sys.stderr)
        return {}
    cap = data.get("capture")
    if not isinstance(cap, dict):
        return {}
    return {k: cap[k] for k in CONFIG_KEYS if k in cap and cap[k] not in (None, "")}


def save_config(iface: Optional[str] = None, queue_maxsize: Optional[int] = None,
                bpf: Optional[str] = None, path: Optional[str] = None) -> str:
    """把当前设置写进 config.json（保留其它段），返回写入路径。"""
    path = path or CONFIG_PATH
    data: dict = {}
    if os.path.exists(path):
        try:
            with open(path, "r", encoding="utf-8") as f:
                data = json.load(f) or {}
        except Exception:
            data = {}
    cap = data.get("capture")
    if not isinstance(cap, dict):
        cap = {}
    if iface:
        cap["iface"] = iface
    if queue_maxsize:
        cap["queue_maxsize"] = int(queue_maxsize)
    if bpf:
        cap["bpf"] = bpf
    data["capture"] = cap
    with open(path, "w", encoding="utf-8") as f:
        json.dump(data, f, ensure_ascii=False, indent=2)
    return path


PROBE_TIMEOUT_MS = 200


class CaptureError(Exception):
    """抓包相关错误，message 为可直接展示给用户的中文说明。"""


# ---------------------------------------------------------------- 网卡与环境


# Windows 上会枚举出一堆过滤驱动伪接口（WAN Miniport、Wi-Fi Direct、
# Hyper-V、VirtualBox、QoS Packet Scheduler…），它们抓不到真实流量，
# 但会排在列表前面把人带偏。这里自动标出来并排到后面。
_VIRTUAL_HINTS = (
    "wan miniport", "wi-fi direct", "loopback", "hyper-v", "virtualbox",
    "bluetooth", "kernel debug", "teredo", "6to4", "ip-https", "sstp",
    "ikev2", "l2tp", "pptp", "pppoe", "ndis", "filter", "qos packet scheduler",
    "virtual", "vswitch", "miniport",
)


def _is_virtual_iface(name: str, description: str) -> bool:
    text = f"{name} {description}".lower()
    return any(hint in text for hint in _VIRTUAL_HINTS)


def list_ifaces() -> list[dict]:
    """返回网卡清单，按"能不能用来演示"排序。

    每项：{name, description, ips, is_loopback, is_virtual, recommended}
    - name：传给 sniffer 用的真实标识（Windows 是 \\Device\\NPF_{GUID}）
    - description：给人看的名字（"以太网"、"WLAN"、"Intel(R) Wi-Fi 6E ..."）
    - recommended：建议首选，C 的页面把这一项排最前 / 加个标记
    """
    items: list[dict] = []
    for name in get_if_list():
        try:
            iface = resolve_iface(name)
        except Exception:
            continue
        desc = (getattr(iface, "description", "") or name).strip()
        ips = _iface_ips(iface, name)
        # 不能用 flags & 0x8 判断：Windows 网卡标志位与 POSIX IFF 语义不同，
        # 会把真实无线网卡误判成环回（实测 AX211 中招）。只认名字和 IP。
        loopback = ("loopback" in name.lower() or "loopback" in desc.lower()
                    or (bool(ips) and all(ip.startswith("127.") or ip == "::1" for ip in ips)))
        virtual = _is_virtual_iface(name, desc)
        items.append(
            {
                "name": name,
                "description": desc,
                "ips": ips,
                "is_loopback": loopback,
                "is_virtual": virtual,
                # 169.254.x.x 是"网线没插好"的自动地址，不能用于演示
                "recommended": (not virtual) and (not loopback)
                and any(not ip.startswith("169.254.") for ip in ips),
            }
        )
    # 排前面：推荐 → 有 IP → 其余；同组内按描述字母序，保证每次输出稳定
    items.sort(key=lambda i: (not i["recommended"], not i["ips"], i["description"]))
    return items


def _iface_ips(iface=None, name: str = "") -> list[str]:
    """取网卡的 IPv4 地址。scapy 的 iface.ips 是 {4: [...], 6: [...]}，
    比 conf.route.route() 稳定（后者在 Windows 无线网卡上常返回 0.0.0.0）。"""
    try:
        raw = getattr(iface, "ips", None)
        if raw:
            v4 = list(raw.get(4, [])) if hasattr(raw, "get") else [i for i in raw if ":" not in i]
            v4 = [str(a) for a in v4 if a and str(a) != "0.0.0.0"]
            if v4:
                return v4
    except Exception:
        pass
    try:
        return [str(a) for a in conf.route.route(name)[1:3] if a and str(a) != "0.0.0.0"]
    except Exception:
        return []


def resolve_capture_iface(value: Optional[str]) -> str:
    """把用户给的网卡名解析成 scapy 认的 name。

    支持三种写法：完整 NPF 名、"以太网"这种 description、留空自动选第一个
    有 IP 且非环回的网卡。找不到就抛 CaptureError（中文原因）。
    """
    if not value:
        items = list_ifaces()
        if not items:
            raise CaptureError("本机没有找到任何可抓包的网卡，请确认已安装 Npcap。")
        for cand in items:                     # list_ifaces 已按可用性排好序
            if cand["recommended"]:
                return cand["name"]
        for cand in items:                     # 退一步：有 IP 的真实网卡
            if not cand["is_virtual"] and not cand["is_loopback"]:
                return cand["name"]
        return items[0]["name"]

    for item in list_ifaces():
        if value == item["name"] or value.lower() == item["description"].lower():
            return item["name"]

    try:  # 允许 scapy 自己按 IP / 前缀解析
        resolve_iface(value)
        if value in get_if_list():
            return value
    except Exception:
        pass

    available = "、".join(f"{i['description']}" for i in list_ifaces()) or "（无）"
    raise CaptureError(f"网卡「{value}」不存在。可用网卡：{available}")


def explain_capture_error(exc: BaseException) -> str:
    """把底层英文异常翻译成演示时能直接念出来的中文原因。"""
    msg = f"{type(exc).__name__}: {exc}"
    low = msg.lower()
    if "not permitted" in low or "permission" in low or "operation not permitted" in low:
        return ("没有抓包权限。Windows 请以管理员身份运行并确认已安装 Npcap；"
                "Linux 请用 root 或授予 CAP_NET_RAW 能力。")
    if "no libpcap provider" in low or "libpcap" in low or "npcap" in low:
        return "缺少 libpcap/Npcap 驱动，无法实时抓包；请安装 Npcap 后重启程序（离线分析不受影响）。"
    if "not found" in low or "no such device" in low:
        return f"网卡不存在或已被禁用：{exc}"
    if "not running" in low:
        return "抓包已经停止，无需重复停止。"
    return f"抓包异常：{msg}"


def preflight_capture(iface: str) -> None:
    """开一个抓包 socket 立刻关掉，把权限/驱动问题提前暴露。

    不做这一步的话，scapy 的 AsyncSniffer 会在后台线程里静默失败，
    表现为"显示在抓包、实际 0 个包"，演示时最难解释。
    """
    try:
        sock = conf.L2listen(iface=iface, filter=None)
    except Exception as exc:
        raise CaptureError(explain_capture_error(exc)) from exc
    else:
        try:
            sock.close()
        except Exception:
            pass


def _has_pcap_provider() -> bool:
    """scapy 的 use_pcap 在 2.5+ 是属性，旧版本是配置项，两种都兼容。"""
    val = getattr(conf, "use_pcap", None)
    if callable(val):
        try:
            val = val()
        except Exception:
            return False
    return bool(val)


def check_capture_env() -> dict:
    """启动前的环境自检，结果直接写进状态快照，供页面显示。"""
    info = {
        "scapy_version": getattr(conf, "version", "未知"),
        "libpcap_provider": _has_pcap_provider(),
        "iface_count": len(list_ifaces()),
        "admin_hint": "",
    }
    if not info["libpcap_provider"]:
        info["admin_hint"] = "当前没有可用的 libpcap/Npcap 提供者，实时抓包可能失败；请安装 Npcap 并以管理员身份运行。"
    return info


# ---------------------------------------------------------------- 采集统计


@dataclass
class SnifferStats:
    """采集侧计数。字段名一旦定下不再改（变更需通知 B、C）。"""

    started_at: Optional[float] = None
    stopped_at: Optional[float] = None
    captured: int = 0          # 网卡上收到的原始包数
    converted: int = 0         # 转换成功并入队（含 partial）
    skipped: int = 0           # 判定为不支持的包（如 ARP/非 IP），不入队
    convert_failed: int = 0    # 转换异常（已捕获，不影响运行）
    enqueued: int = 0          # 实际入队数
    dropped: int = 0           # 队列满而丢弃的包数
    last_error: str = ""
    last_error_at: Optional[float] = None
    queue_maxsize: int = DEFAULT_QUEUE_MAXSIZE

    def as_dict(self) -> dict:
        elapsed = 0.0
        if self.started_at:
            end = self.stopped_at or time.time()
            elapsed = round(end - self.started_at, 2)
        return {
            "started_at": self.started_at,
            "stopped_at": self.stopped_at,
            "elapsed_s": elapsed,
            "captured": self.captured,
            "converted": self.converted,
            "skipped": self.skipped,
            "convert_failed": self.convert_failed,
            "enqueued": self.enqueued,
            "dropped": self.dropped,
            "queue_maxsize": self.queue_maxsize,
            "last_error": self.last_error,
            "last_error_at": self.last_error_at,
        }


# ---------------------------------------------------------------- 抓包主体


class PacketSniffer:
    """指定网卡抓包，把每个包转成 dict 放进有界队列。

    线程安全：start/stop/stats 都可能被主线程或 Web 线程调用，内部加锁。
    """

    def __init__(
        self,
        iface: Optional[str] = None,
        queue_maxsize: Optional[int] = None,
        bpf: Optional[str] = None,
        promisc: bool = False,
        on_error: Optional[Callable[[str], None]] = None,
        config_path: Optional[str] = None,
    ) -> None:
        cfg = load_config(config_path)
        env_iface = os.environ.get("SNIFFER_IFACE") or None
        # 优先级：显式参数 > 环境变量 > 配置文件 > 自动选择（start() 时才做）
        self.iface = iface or env_iface or cfg.get("iface") or None
        self.iface_source = ("参数" if iface else "环境变量" if env_iface
                             else "配置文件" if cfg.get("iface") else "自动选择")
        self.queue_maxsize = max(1, int(queue_maxsize or cfg.get("queue_maxsize")
                                   or DEFAULT_QUEUE_MAXSIZE))
        self.bpf = bpf or cfg.get("bpf") or None
        self.promisc = promisc
        self.pkt_queue: "queue.Queue[dict]" = queue.Queue(maxsize=self.queue_maxsize)
        self.stats_data = SnifferStats(queue_maxsize=self.queue_maxsize)
        self._sniffer: Optional[AsyncSniffer] = None
        self._lock = threading.Lock()
        self._index = 0
        self._stop_event = threading.Event()
        self._on_error = on_error

    # --- 生命周期 ---

    @property
    def running(self) -> bool:
        return self._sniffer is not None and bool(getattr(self._sniffer, "running", False))

    def start(self) -> None:
        if self.running:
            raise CaptureError("抓包已经在运行中，请先 stop()。")
        if self.iface is None:
            self.iface = resolve_capture_iface(None)
        try:
            self.iface = resolve_capture_iface(self.iface)
        except CaptureError:
            raise
        except Exception as exc:
            raise CaptureError(f"网卡初始化失败：{exc}") from exc

        preflight_capture(self.iface)   # 权限/驱动问题在这里就报错，不要等到后台线程

        self._index = 0
        self._stop_event.clear()
        with self._lock:
            self.stats_data = SnifferStats(
                started_at=time.time(), queue_maxsize=self.queue_maxsize
            )
            # 队列里可能残留上次的包，清掉避免消费者读到旧数据
            self._drain_queue()

        try:
            self._sniffer = AsyncSniffer(
                iface=self.iface,
                prn=self._on_packet,
                store=False,
                promisc=self.promisc,
                filter=self.bpf,
            )
            self._sniffer.start()
        except Exception as exc:
            self._sniffer = None
            raise CaptureError(explain_capture_error(exc)) from exc

        # 给底层线程一点时间真正起来，失败就当场抛出来，不要让人以为在抓
        time.sleep(0.3)
        inner = getattr(self._sniffer, "exception", None)
        if inner is not None:
            self._sniffer = None
            raise CaptureError(explain_capture_error(inner))
        if not self.running:
            self._sniffer = None
            raise CaptureError(
                "抓包线程未能启动。常见原因：网卡已被占用、需要管理员权限、"
                "或网卡处于禁用状态。"
            )

    def stop(self, timeout: float = 2.0) -> None:
        """停止抓包。幂等，可重复调用。"""
        self._stop_event.set()
        sniffer, self._sniffer = self._sniffer, None
        if sniffer is None:
            return
        try:
            sniffer.stop(join=True)
        except Exception as exc:  # 停止失败不该让程序崩
            self._record_error(explain_capture_error(exc))
        with self._lock:
            if self.stats_data.stopped_at is None:
                self.stats_data.stopped_at = time.time()

    def wait(self, timeout: Optional[float] = None) -> None:
        """等抓包线程自行结束（例如 duration 到期或 stop_filter 命中）。"""
        sniffer = self._sniffer
        if sniffer is None:
            return
        for _ in range(int((timeout or 60) * 10)):
            if self._stop_event.is_set() or not self.running:
                break
            time.sleep(0.1)
        with self._lock:
            if self.stats_data.stopped_at is None:
                self.stats_data.stopped_at = time.time()

    # --- 单包处理（核心生产逻辑） ---

    def _on_packet(self, pkt) -> None:
        """AsyncSniffer 回调：每个包都会走这里，任何异常都不能外抛。"""
        ts = float(getattr(pkt, "time", 0.0))
        rec: Optional[PacketRecord] = None
        try:
            self._index += 1
            rec = parse_packet(pkt, self._index)
        except Exception as exc:  # parse_packet 本身不会抛，这里是双保险
            with self._lock:
                self.stats_data.captured += 1
                self.stats_data.convert_failed += 1
                self.stats_data.last_error = f"单包转换失败：{exc}"
                self.stats_data.last_error_at = ts
            return

        with self._lock:
            self.stats_data.captured += 1
            if rec.status == "skipped":
                self.stats_data.skipped += 1
                return
            self.stats_data.converted += 1

        record = rec.to_dict()
        record["capture_time"] = ts  # 与 timestamp 同值，明示这是抓包时刻
        try:
            self.pkt_queue.put_nowait(record)       # 满则丢新包，绝不阻塞
        except queue.Full:
            with self._lock:
                self.stats_data.dropped += 1
                if not self.stats_data.last_error:
                    self.stats_data.last_error = "队列已满，正在丢弃新到的包"
                    self.stats_data.last_error_at = ts
        else:
            with self._lock:
                self.stats_data.enqueued += 1

    def _drain_queue(self) -> None:
        while True:
            try:
                self.pkt_queue.get_nowait()
            except queue.Empty:
                return

    def _record_error(self, msg: str) -> None:
        with self._lock:
            self.stats_data.last_error = msg
            self.stats_data.last_error_at = time.time()
        if self._on_error:
            self._on_error(msg)

    # --- 对 B / C 暴露的只读视图 ---

    def stats(self) -> dict:
        with self._lock:
            data = self.stats_data.as_dict()
            data["queue_len"] = self._queue_len()
            data["running"] = self.running
            data["iface"] = self.iface
            data["index"] = self._index
        return data

    def _queue_len(self) -> int:
        try:
            return int(self.pkt_queue.qsize())
        except Exception:
            return -1


# ---------------------------------------------------------------- 回放（无权限也能联调）


def replay(
    pcap_path: str,
    queue_maxsize: int = DEFAULT_QUEUE_MAXSIZE,
    limit: Optional[int] = None,
) -> tuple[list[dict], SnifferStats]:
    """把 pcap 文件当作"网卡"喂进同一条生产链路。

    用途：没有抓包权限的机器上验证"转换 → 入队 → 计数"是否正确，
    也用于 11/29 回归（实时链路与离线结果必须一致）。
    """
    sniffer = PacketSniffer(queue_maxsize=queue_maxsize)
    sniffer.stats_data = SnifferStats(
        started_at=time.time(), queue_maxsize=queue_maxsize
    )
    records: list[dict] = []
    with PcapReader(pcap_path) as reader:
        for i, pkt in enumerate(reader, 1):
            if limit and i > limit:
                break
            sniffer._on_packet(pkt)
            while True:
                try:
                    records.append(sniffer.pkt_queue.get_nowait())
                except queue.Empty:
                    break
    sniffer.stats_data.stopped_at = time.time()
    return records, sniffer.stats_data


# ---------------------------------------------------------------- CLI


def _main(argv: Optional[Iterable[str]] = None) -> int:
    ap = argparse.ArgumentParser(description="成员 A：实时抓包 → 单包转换 → 有界队列")
    ap.add_argument("--list", action="store_true", help="列出可用网卡")
    ap.add_argument("--iface", default=None, help="网卡名或描述，如 以太网 / WLAN")
    ap.add_argument("--duration", type=float, default=10, help="抓包秒数，默认 10")
    ap.add_argument("--bpf", default=None, help="BPF 过滤，如 tcp udp dns")
    ap.add_argument("--queue-max", type=int, default=None)
    ap.add_argument("--save-config", action="store_true", help="把当前 iface/queue-max 写入 config.json")
    ap.add_argument("--show-config", action="store_true", help="显示配置文件路径与内容")
    ap.add_argument("--replay", default=None, help="改用 pcap 文件回放（无需权限）")
    args = ap.parse_args(list(argv) if argv is not None else None)

    if args.show_config:
        print(f"配置文件：{CONFIG_PATH}（{'存在' if os.path.exists(CONFIG_PATH) else '不存在'}）")
        print(json.dumps(load_config(), ensure_ascii=False, indent=2))
        print(f"环境变量 SNIFFER_IFACE：{os.environ.get('SNIFFER_IFACE') or '（未设置）'}")
        return 0

    if args.save_config:
        if not args.iface:
            print("[失败] --save-config 需要同时给出 --iface，例如："
                  'python sniffer.py --save-config --iface "以太网"')
            return 2
        path = save_config(args.iface, args.queue_max, args.bpf)
        print(f"已写入 {path}")
        print(json.dumps(load_config(), ensure_ascii=False, indent=2))
        return 0

    if args.list:
        print(f"sniffer v{__version__}")
        print(f"{'序号':<4}{'标记':<8}{'描述':<46}IP")
        for i, it in enumerate(list_ifaces(), 1):
            if it["recommended"]:
                mark = "推荐"
            elif it["is_virtual"]:
                mark = "虚拟"
            elif it["is_loopback"]:
                mark = "环回"
            else:
                mark = ""
            print(f"{i:<4}{mark:<8}{it['description']:<46}{', '.join(it['ips']) or '（无 IP）'}")
        print("\n说明：演示请用标「推荐」的网卡；name 太长的可在 --iface 后直接写描述名。")
        return 0

    env = check_capture_env()
    print(f"sniffer v{__version__}｜scapy {env['scapy_version']}｜网卡 {env['iface_count']} 个｜"
          f"libpcap/Npcap {'可用' if env['libpcap_provider'] else '不可用'}")
    if env["admin_hint"]:
        print(env["admin_hint"])

    if args.replay:
        records, st = replay(args.replay, args.queue_max)
        print(f"\n回放 {args.replay}：{st.captured} 个原始包 → 转换成功 {st.converted}、"
              f"跳过 {st.skipped}、失败 {st.convert_failed}、入队 {st.enqueued}、丢弃 {st.dropped}")
        for r in records[:5]:
            print(f"  #{r['index']:<4}{format_ts(r['timestamp'])}  "
                  f"{r['src_ip'] or '-':>15}:{str(r['src_port'] or '-'):<6}→"
                  f"{r['dst_ip'] or '-':>15}:{str(r['dst_port'] or '-'):<6}"
                  f"{r['protocol']:<5}{r['length']:>5}B")
        return 0

    sniffer = PacketSniffer(args.iface, queue_maxsize=args.queue_max, bpf=args.bpf)
    print(f"\n开始抓包：{sniffer.iface or '（自动选择网卡）'}（来源：{sniffer.iface_source}），"
          f"持续 {args.duration:g} 秒"
          f"（Ctrl+C 可提前停止）")
    try:
        sniffer.start()
    except CaptureError as exc:
        print(f"[失败] {exc}")
        return 2

    t0 = time.time()
    drained = 0
    try:
        while time.time() - t0 < args.duration:
            try:
                sniffer.pkt_queue.get(timeout=0.5)
                drained += 1
            except queue.Empty:
                pass
    except KeyboardInterrupt:
        print("\n收到 Ctrl+C，停止抓包…")
    finally:
        sniffer.stop()

    st = sniffer.stats()
    print(f"\n采集 {st['elapsed_s']:g}s｜原始 {st['captured']} 包｜转换成功 {st['converted']}"
          f"｜跳过 {st['skipped']}｜失败 {st['convert_failed']}｜入队 {st['enqueued']}"
          f"｜丢弃 {st['dropped']}｜队列剩 {st['queue_len']}/{st['queue_maxsize']}")
    if st["last_error"]:
        print(f"最近错误：{st['last_error']}")
    if drained != st["enqueued"]:
        print(f"（本次演示消费了 {drained} 条，剩余留在队列里）")
    return 0 if st["captured"] > 0 else 3


if __name__ == "__main__":
    raise SystemExit(_main())

