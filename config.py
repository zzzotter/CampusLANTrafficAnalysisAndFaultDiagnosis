"""异常检测规则的默认阈值。"""

DNS_FAILURE_WINDOW_SECONDS = 60
DNS_FAILURE_THRESHOLD = 5

TCP_RESET_WINDOW_SECONDS = 60
TCP_RESET_RATE_THRESHOLD = 0.50  # 0.50 表示 50%
TCP_RESET_MIN_PACKETS = 4

# 展示用：时间趋势的统计桶宽（秒）
TREND_BUCKET_SECONDS = 60

# 实时统计与页面快照
LIVE_WINDOW_SECONDS = 60
LIVE_REFRESH_SECONDS = 1.0
LIVE_MAX_PACKET_RECORDS = 20_000
LIVE_MAX_ALERTS = 100
LIVE_TREND_BUCKET_SECONDS = 1
LIVE_MAX_TREND_POINTS = 61

# 演示目标。联调时根据实际网关和 DNS 地址调整。
PROBE_TIMEOUT_SECONDS = 2.0
PROBE_INTERVAL_SECONDS = 10.0
PROBE_TARGETS = (
    {"name": "网关", "type": "icmp", "target": "192.168.1.1"},
    {"name": "DNS", "type": "dns", "target": "114.114.114.114", "query": "example.com"},
    {"name": "外网", "type": "tcp", "target": "1.1.1.1", "port": 443},
)
