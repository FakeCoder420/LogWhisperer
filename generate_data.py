"""
LogWhisperer — generate_data.py
================================
Generates mock_server_logs.csv containing 1,000 rows of simulated Nginx web
server access logs.

Traffic composition
-------------------
  • 979 rows  → normal, randomised HTTP 200 traffic
  •  20 rows  → brute-force cluster: consecutive HTTP 401 requests to
                /admin/login from 192.168.1.50 within a tight time window
  •   1 row   → successful HTTP 200 login to /admin/login from the same IP
                immediately after the 20 failures

All timestamps are in chronological order.
"""

import csv
import random
from datetime import datetime, timedelta

# ── Configuration ──────────────────────────────────────────────────────────────

OUTPUT_FILE       = "mock_server_logs.csv"
TOTAL_ROWS        = 1000
ATTACK_IP         = "192.168.1.50"
ATTACK_ENDPOINT   = "/admin/login"
BRUTE_FORCE_COUNT = 20          # number of HTTP 401 rows
ATTACK_WINDOW_SEC = 45          # entire brute-force burst fits inside this many seconds

# Where to inject the attack cluster inside the timeline (row index, 0-based).
# Placed around 70 % through the log so it's not trivially at the end.
ATTACK_INJECT_AT  = 700

RANDOM_SEED = 42                # reproducible output; remove for fresh data each run

# Log start time — set to a plausible past date for realism
LOG_START = datetime(2026, 10, 2, 9, 0, 0)

# ── Realistic pool data ────────────────────────────────────────────────────────

NORMAL_IPS = [
    "10.0.0." + str(i) for i in range(1, 51)
] + [
    "172.16." + str(a) + "." + str(b)
    for a in range(0, 5)
    for b in range(1, 11)
] + [
    f"203.0.113.{i}" for i in range(1, 30)
]

ENDPOINTS = [
    "/",
    "/index.html",
    "/about",
    "/contact",
    "/products",
    "/products/detail",
    "/blog",
    "/blog/post-1",
    "/blog/post-2",
    "/api/v1/users",
    "/api/v1/items",
    "/static/css/main.css",
    "/static/js/app.js",
    "/favicon.ico",
    "/images/logo.png",
    "/search",
    "/checkout",
    "/cart",
    "/login",
    "/register",
    "/dashboard",
    "/profile",
    "/settings",
    "/healthz",
]

METHODS = ["GET", "POST", "PUT", "DELETE", "PATCH"]
METHOD_WEIGHTS = [70, 18, 4, 4, 4]        # realistic distribution

STATUS_NORMAL = [200, 200, 200, 200, 301, 302, 304, 400, 403, 404, 500]
STATUS_WEIGHTS = [60, 10, 5, 5, 4, 4, 4, 2, 2, 3, 1]

USER_AGENTS = [
    # Chrome / Windows
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
    # Firefox / Linux
    "Mozilla/5.0 (X11; Linux x86_64; rv:125.0) Gecko/20100101 Firefox/125.0",
    # Safari / macOS
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_4_1) AppleWebKit/605.1.15 "
    "(KHTML, like Gecko) Version/17.4.1 Safari/605.1.15",
    # Edge / Windows
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36 Edg/124.0.0.0",
    # Mobile Chrome / Android
    "Mozilla/5.0 (Linux; Android 14; Pixel 8) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/124.0.0.0 Mobile Safari/537.36",
    # iOS Safari
    "Mozilla/5.0 (iPhone; CPU iPhone OS 17_4_1 like Mac OS X) "
    "AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4 Mobile/15E148 Safari/604.1",
    # Curl (automated / scripted — used by the attacker)
    "curl/8.7.1",
    # Python requests (another automation signal)
    "python-requests/2.31.0",
    # Googlebot
    "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)",
    # wget
    "Wget/1.21.4",
]

# The attacker uses a generic curl-like agent throughout the brute-force burst
ATTACK_USER_AGENT = "curl/8.7.1"


# ── Helpers ────────────────────────────────────────────────────────────────────

def random_ip() -> str:
    return random.choice(NORMAL_IPS)


def random_normal_row(ts: datetime) -> dict:
    method = random.choices(METHODS, weights=METHOD_WEIGHTS, k=1)[0]
    status = random.choices(STATUS_NORMAL, weights=STATUS_WEIGHTS, k=1)[0]
    # POST / PUT / PATCH are unlikely on static assets
    if method in ("PUT", "DELETE", "PATCH"):
        endpoint = random.choice([e for e in ENDPOINTS if e.startswith("/api") or e in ("/login", "/register", "/settings", "/profile", "/cart")])
    else:
        endpoint = random.choice(ENDPOINTS)
    return {
        "timestamp":  ts.strftime("%Y-%m-%d %H:%M:%S"),
        "ip_address": random_ip(),
        "method":     method,
        "endpoint":   endpoint,
        "status_code": status,
        "user_agent": random.choice(USER_AGENTS),
    }


def build_timeline(n_normal_before: int, n_normal_after: int) -> list[datetime]:
    """
    Build a strictly-increasing timestamp list for the full 1 000 rows.

    The attack window (20 brute-force + 1 success = 21 rows) is allocated
    ATTACK_WINDOW_SEC seconds inside the overall timeline.
    """
    # Spread the entire log over roughly 8 hours
    total_seconds = 8 * 3600

    # Proportion of time before / after the attack block
    before_fraction = ATTACK_INJECT_AT / TOTAL_ROWS
    after_fraction  = 1.0 - before_fraction

    before_secs  = int(total_seconds * before_fraction)
    attack_secs  = ATTACK_WINDOW_SEC
    after_secs   = int(total_seconds * after_fraction) - attack_secs

    # ── Before-attack timestamps ──────────────────────────────────────────────
    before_gaps = sorted(random.uniform(0.5, before_secs / max(n_normal_before, 1) * 2)
                         for _ in range(n_normal_before))
    # Normalise so they sum to before_secs
    gap_sum = sum(before_gaps)
    before_gaps = [g * before_secs / gap_sum for g in before_gaps]

    before_ts: list[datetime] = []
    current = LOG_START
    for g in before_gaps:
        current += timedelta(seconds=g)
        before_ts.append(current)

    attack_start = before_ts[-1] if before_ts else LOG_START

    # ── Attack timestamps (tight burst) ───────────────────────────────────────
    attack_rows = BRUTE_FORCE_COUNT + 1          # 20 failures + 1 success
    attack_gap  = ATTACK_WINDOW_SEC / attack_rows
    attack_ts   = [
        attack_start + timedelta(seconds=i * attack_gap + random.uniform(0.1, attack_gap * 0.4))
        for i in range(attack_rows)
    ]

    # ── After-attack timestamps ───────────────────────────────────────────────
    after_start = attack_ts[-1]
    after_gaps  = sorted(random.uniform(0.5, after_secs / max(n_normal_after, 1) * 2)
                         for _ in range(n_normal_after))
    gap_sum = sum(after_gaps)
    after_gaps  = [g * after_secs / gap_sum for g in after_gaps]

    after_ts: list[datetime] = []
    current = after_start
    for g in after_gaps:
        current += timedelta(seconds=g)
        after_ts.append(current)

    return before_ts, attack_ts, after_ts


# ── Main ───────────────────────────────────────────────────────────────────────

def main() -> None:
    random.seed(RANDOM_SEED)

    n_before = ATTACK_INJECT_AT                          # 700 normal rows
    n_after  = TOTAL_ROWS - ATTACK_INJECT_AT - (BRUTE_FORCE_COUNT + 1)  # 279 normal rows

    print(f"[*] Building timeline …")
    before_ts, attack_ts, after_ts = build_timeline(n_before, n_after)

    rows: list[dict] = []

    # ── 700 normal rows before the attack ─────────────────────────────────────
    print(f"[*] Generating {n_before} normal rows (pre-attack) …")
    for ts in before_ts:
        rows.append(random_normal_row(ts))

    # ── Brute-force burst: 20 × HTTP 401 ──────────────────────────────────────
    print(f"[*] Injecting {BRUTE_FORCE_COUNT}-request brute-force cluster …")
    for ts in attack_ts[:BRUTE_FORCE_COUNT]:
        rows.append({
            "timestamp":   ts.strftime("%Y-%m-%d %H:%M:%S"),
            "ip_address":  ATTACK_IP,
            "method":      "POST",
            "endpoint":    ATTACK_ENDPOINT,
            "status_code": 401,
            "user_agent":  ATTACK_USER_AGENT,
        })

    # ── Final successful login: HTTP 200 ──────────────────────────────────────
    print(f"[*] Injecting attacker's successful login (HTTP 200) …")
    rows.append({
        "timestamp":   attack_ts[BRUTE_FORCE_COUNT].strftime("%Y-%m-%d %H:%M:%S"),
        "ip_address":  ATTACK_IP,
        "method":      "POST",
        "endpoint":    ATTACK_ENDPOINT,
        "status_code": 200,
        "user_agent":  ATTACK_USER_AGENT,
    })

    # ── 279 normal rows after the attack ──────────────────────────────────────
    print(f"[*] Generating {n_after} normal rows (post-attack) …")
    for ts in after_ts:
        rows.append(random_normal_row(ts))

    # ── Sanity checks ─────────────────────────────────────────────────────────
    assert len(rows) == TOTAL_ROWS, f"Expected {TOTAL_ROWS} rows, got {len(rows)}"

    attack_rows_in_csv = [
        r for r in rows
        if r["ip_address"] == ATTACK_IP and r["endpoint"] == ATTACK_ENDPOINT
    ]
    assert len(attack_rows_in_csv) == BRUTE_FORCE_COUNT + 1

    # ── Write CSV ─────────────────────────────────────────────────────────────
    fieldnames = ["timestamp", "ip_address", "method", "endpoint", "status_code", "user_agent"]
    print(f"[*] Writing {OUTPUT_FILE} …")
    with open(OUTPUT_FILE, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(rows)

    # ── Summary ───────────────────────────────────────────────────────────────
    print()
    print("=" * 60)
    print("  LogWhisperer — Dataset Generation Complete")
    print("=" * 60)
    print(f"  Output file   : {OUTPUT_FILE}")
    print(f"  Total rows    : {len(rows)}")
    print(f"  Normal rows   : {len(rows) - (BRUTE_FORCE_COUNT + 1)}")
    print(f"  Attack rows   : {BRUTE_FORCE_COUNT} × HTTP 401  +  1 × HTTP 200")
    print(f"  Attacker IP   : {ATTACK_IP}")
    print(f"  Attack target : {ATTACK_ENDPOINT}")
    print(f"  Burst window  : ~{ATTACK_WINDOW_SEC} seconds")
    attack_start_str = attack_rows_in_csv[0]["timestamp"]
    attack_end_str   = attack_rows_in_csv[-1]["timestamp"]
    print(f"  Burst range   : {attack_start_str}  ->  {attack_end_str}")
    print("=" * 60)


if __name__ == "__main__":
    main()
