"""成员 C：Flask Web 骨架与 /api/state 接口（11/27 交付）。

职责：
- /api/state  返回只读状态快照（JSON），结构即与 B 的契约；
- /            渲染前端页面；
- /api/health  健康检查。

当前阶段（11/27）：B 的真实快照还没就绪，`get_snapshot()` 返回固定格式的样例状态，
用于打通「页面 → 接口 → 展示」链路。11/28 起调用 `set_snapshot_provider(B.get_snapshot)`
接入真实数据，页面无需改动，只要 B 的快照保持相同字段即可。

启动方式：
    python web/app.py                         # 直接启动，http://127.0.0.1:8000
    或由 main.py --live --web 统一启动：from web.app import app
"""

from __future__ import annotations

import time
from typing import Callable, Optional

from flask import Flask, jsonify, render_template

app = Flask(__name__)

# ---------------------------------------------------------------------------
# 状态快照契约（与 B 约定，B 的真实快照必须包含这些字段）
#
#   updated_at    float  最近一次状态更新时间（Unix 秒）
#   probes        list   主动探测结果：target/type/status/latency_ms/last_probe_at/error
#   window        dict   最近时间窗内的包数和字节数：seconds/packets/bytes
#   alerts        list   告警及依据：type/device_ip/start_time/end_time/reason
#   queue         dict   队列长度、丢弃数、采集错误信息：length/dropped/capture_errors/last_error
# ---------------------------------------------------------------------------

SAMPLE_STATE: dict = {
    "updated_at": 1783072800.0,
    "source": "sample",  # sample=样例数据，live=真实快照（页面据此显示角标）
    "probes": [
        {
            "target": "网关 192.168.1.1",
            "type": "icmp",
            "status": "ok",           # ok / fail
            "latency_ms": 3.2,
            "last_probe_at": 1783072799.0,
            "error": None,
        },
        {
            "target": "DNS 114.114.114.114",
            "type": "dns",
            "status": "fail",
            "latency_ms": None,
            "last_probe_at": 1783072799.0,
            "error": "解析超时（2 秒）",
        },
        {
            "target": "外网 www.baidu.com:443",
            "type": "tcp",
            "status": "ok",
            "latency_ms": 21.5,
            "last_probe_at": 1783072799.0,
            "error": None,
        },
    ],
    "window": {
        "seconds": 60,
        "packets": 1234,
        "bytes": 456789,
    },
    "alerts": [
        {
            "type": "DNS 失败",
            "device_ip": "192.168.1.35",
            "start_time": 1783072740.0,
            "end_time": 1783072799.0,
            "reason": "60 秒内收到 8 次 DNS 失败响应，阈值为 5 次",
        },
    ],
    "queue": {
        "length": 0,
        "dropped": 0,
        "capture_errors": 0,
        "last_error": None,
    },
}

# 真实快照来源。B 的消费者线程就绪后，C 调用 set_snapshot_provider 接入；
# 在此之前保持 None，接口返回样例状态。
_snapshot_provider: Optional[Callable[[], dict]] = None


def set_snapshot_provider(provider: Callable[[], dict]) -> None:
    """接入 B 的真实只读快照：set_snapshot_provider(live_state.get_snapshot)。"""
    global _snapshot_provider
    _snapshot_provider = provider


def get_snapshot() -> dict:
    """返回当前状态快照。未接真实数据前返回固定样例。"""
    if _snapshot_provider is not None:
        return _snapshot_provider()
    # 样例模式：更新时间用当前时刻，其余字段保持固定示例值
    snapshot = dict(SAMPLE_STATE)
    snapshot["updated_at"] = time.time()
    return snapshot


@app.get("/api/state")
def api_state():
    """只读状态快照。接入真实数据后结构不变，页面无需改动。"""
    return jsonify(get_snapshot())


@app.get("/api/health")
def api_health():
    return jsonify({"ok": True})


@app.get("/")
def index():
    return render_template("index.html")


if __name__ == "__main__":
    # 骨架自测入口；正式启动由 main.py --live --web 统一完成。
    # debug=False：课程演示不要开启调试模式，避免意外代码执行。
    app.run(host="127.0.0.1", port=8000, debug=False)
