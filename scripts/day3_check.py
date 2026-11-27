"""字段冻结单第 4 节承诺的冒烟验证：python scripts/day3_check.py

四项检查：
1. 多示例结果一致        —— normal.pcap 与 normal.pcapng 解析结果完全相同
2. 坏输入不中断          —— 空文件、损坏文件、非 IP 文件都给出结果而不是崩溃
3. 字段与冻结清单一致    —— 每条记录的键集合恰好等于 核心字段 ∪ 扩展字段
4. 性能可用              —— 重复解析同一文件，吞吐量在可接受范围

全部通过时打印 4/4 并以退出码 0 结束；任一项失败以退出码 1 结束。
"""

import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))          # 必须在 import parser 之前

from parser import (                   # noqa: E402
    CORE_FIELDS,
    EXTRA_FIELDS,
    PcapError,
    parse_pcap,
    parse_pcap_detailed,
)

SAMPLES = ROOT / "samples"
results = []


def check(name):
    def decorator(func):
        try:
            func()
        except Exception as exc:
            results.append((name, False, f"{type(exc).__name__}: {exc}"))
        else:
            results.append((name, True, "ok"))
        return func
    return decorator


@check("1 多示例结果一致")
def _same_between_formats():
    pcap, skipped_pcap = parse_pcap(str(SAMPLES / "normal.pcap"))
    pcapng, skipped_pcapng = parse_pcap(str(SAMPLES / "normal.pcapng"))
    assert pcap == pcapng, "normal.pcap 与 normal.pcapng 解析出的记录不一致"
    assert skipped_pcap == skipped_pcapng, "两种格式的 skipped_count 不一致"


@check("2 坏输入不中断")
def _bad_inputs():
    expect_error = {
        "empty.pcap": "文件为空",
        "corrupt.pcap": None,      # 具体消息由 scapy 版本决定，只要不崩溃
    }
    for name, keyword in expect_error.items():
        result = parse_pcap_detailed(str(SAMPLES / name))
        assert result.error, f"{name} 应当报错"
        if keyword:
            assert keyword in result.error, f"{name} 的错误消息不含「{keyword}」"

    packets, skipped = parse_pcap(str(SAMPLES / "nonip.pcap"))
    assert (len(packets), skipped) == (0, 4), "nonip.pcap 应当全部跳过"

    try:
        parse_pcap(str(SAMPLES / "不存在的文件.pcap"))
    except PcapError:
        pass
    else:
        raise AssertionError("不存在的文件应当抛 PcapError")


@check("3 字段与冻结清单一致")
def _fields():
    expected = set(CORE_FIELDS) | set(EXTRA_FIELDS)
    result = parse_pcap_detailed(str(SAMPLES / "normal.pcap"))
    assert result.packets, "样例没有解析出任何记录"
    for record in result.packets:
        missing = expected - set(record)
        extra = set(record) - expected
        assert not missing, f"缺少字段：{sorted(missing)}"
        assert not extra, f"多出未登记字段：{sorted(extra)}"


@check("4 性能可用")
def _performance():
    rounds = 20
    start = time.perf_counter()
    for _ in range(rounds):
        parse_pcap(str(SAMPLES / "normal.pcap"))
    elapsed = time.perf_counter() - start
    assert elapsed < 10.0, f"{rounds} 次解析耗时 {elapsed:.2f}s，过慢"


def main() -> int:
    passed = sum(1 for _, ok, _ in results if ok)
    total = len(results)
    for name, ok, detail in results:
        mark = "PASS" if ok else "FAIL"
        print(f"[{mark}] {name}" + ("" if ok else f"  →  {detail}"))
    print(f"\n{passed}/{total}")
    return 0 if passed == total else 1


if __name__ == "__main__":
    raise SystemExit(main())
