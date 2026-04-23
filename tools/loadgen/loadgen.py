#!/usr/bin/env python3
import json
import os
import random
import socket
import time
import urllib.request


def env_int(name, default):
    try:
        return int(os.getenv(name, str(default)))
    except Exception:
        return default


def env_float(name, default):
    try:
        return float(os.getenv(name, str(default)))
    except Exception:
        return default


def rand_public_ip():
    while True:
        a = random.randint(1, 223)
        b = random.randint(0, 255)
        c = random.randint(0, 255)
        d = random.randint(1, 254)
        ip = f"{a}.{b}.{c}.{d}"
        if ip.startswith("10.") or ip.startswith("192.168.") or ip.startswith("127."):
            continue
        if 16 <= b <= 31 and a == 172:
            continue
        return ip


def rand_src_ip_outside_target_subnet():
    while True:
        ip = rand_public_ip()
        if not ip.startswith("213.14.158."):
            return ip


def rand_dst_ip_from_target_subnet():
    return f"213.14.158.{random.randint(1, 254)}"


def post_ioc(api_base, ip, source_name, confidence, note):
    url = f"{api_base.rstrip('/')}/api/ioc/ip"
    payload = {
        "ip": ip,
        "source_name": source_name,
        "confidence": str(confidence),
        "note": note,
    }
    data = json.dumps(payload).encode("utf-8")
    headers = {"Content-Type": "application/json"}
    ingest = os.getenv("API_INGEST_TOKEN", "").strip() or os.getenv("API_BEARER_TOKEN", "").strip()
    if ingest:
        headers["X-Api-Ingest-Token"] = ingest
    req = urllib.request.Request(url, data=data, headers=headers, method="POST")
    with urllib.request.urlopen(req, timeout=5) as resp:
        return resp.status


def build_syslog(dst_ip, src_ip):
    return (
        f'date=2019-03-31 time=06:42:54 logid="0002000012" type="traffic" subtype="multicast" '
        f'level="notice" vd="vdom1" eventtime=1554039772 srcip={src_ip} srcport={random.randint(1024,65535)} '
        f'dstip={dst_ip} dstport={random.randint(1000,65000)} srcintf="port25" srcintfrole="undefined" '
        f'dstintf="port3" dstintfrole="undefined" sessionid={random.randint(100000,999999)} proto=17 '
        f'action="accept" policyid=1 policytype="multicast-policy" service="udp/7878" '
        f'dstcountry="Reserved" srccountry="Reserved" trandisp="noop" duration={random.randint(30,300)} '
        f'sentbyte={random.randint(5000,30000)} rcvdbyte={random.randint(100,15000)} '
        f'sentpkt={random.randint(1,40)} rcvdpkt={random.randint(1,20)} appcat="unscanned"'
    )


def main():
    enabled = os.getenv("ENABLED", "0") == "1"
    target_host = os.getenv("SYSLOG_HOST", "syslog-receiver")
    target_port = env_int("SYSLOG_PORT", 514)
    udp_ingest_key = os.getenv("SYSLOG_UDP_SHARED_SECRET", "").strip()
    api_base = os.getenv("IOC_API_BASE", "http://backend:3000")

    eps = max(env_int("EPS", 400), 1)
    duration_seconds = env_int("DURATION_SECONDS", 0)  # 0 = infinite
    mode = os.getenv("MODE", "mixed").strip().lower()  # realtime|retro|mixed
    realtime_ratio = max(0.0, min(env_float("REALTIME_RATIO", 0.5), 1.0))
    ioc_insert_ratio = max(0.0, min(env_float("IOC_INSERT_RATIO", 0.3), 1.0))
    retro_delay_ms = max(env_int("RETRO_DELAY_MS", 1500), 0)
    stats_every_sec = max(env_int("STATS_EVERY_SEC", 10), 1)
    source_name = os.getenv("IOC_SOURCE_NAME", "loadgen-smoke")
    confidence = os.getenv("IOC_CONFIDENCE", "90")
    note = os.getenv("IOC_NOTE", "loadgen random ioc")
    src_ip_rotate_seconds = max(env_int("SRC_IP_ROTATE_SECONDS", 300), 1)

    print(f"[loadgen] config enabled={enabled} mode={mode} eps={eps} duration_s={duration_seconds} ioc_ratio={ioc_insert_ratio} realtime_ratio={realtime_ratio} src_ip_rotate_s={src_ip_rotate_seconds}")
    if not enabled:
        print("[loadgen] ENABLED=0 (idle). Set ENABLED=1 to start traffic.")
        while True:
            time.sleep(30)

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    interval = 1.0 / eps
    t0 = time.time()
    last_stats = t0

    sent = 0
    ioc_posts = 0
    ioc_post_fail = 0

    current_src_ip = rand_src_ip_outside_target_subnet()
    current_src_ip_until = t0 + src_ip_rotate_seconds

    while True:
        now = time.time()
        if duration_seconds > 0 and (now - t0) >= duration_seconds:
            break

        if now >= current_src_ip_until:
            current_src_ip = rand_src_ip_outside_target_subnet()
            current_src_ip_until = now + src_ip_rotate_seconds

        dst_ip = rand_dst_ip_from_target_subnet()
        src_ip = current_src_ip
        do_ioc = random.random() < ioc_insert_ratio

        current_mode = mode
        if mode == "mixed":
            current_mode = "realtime" if random.random() < realtime_ratio else "retro"

        try:
            if do_ioc and current_mode == "realtime":
                post_ioc(api_base, dst_ip, source_name, confidence, note)
                ioc_posts += 1
            msg = build_syslog(dst_ip, src_ip)
            payload = msg.encode("utf-8")
            if udp_ingest_key:
                payload = f"{udp_ingest_key}|".encode("utf-8") + payload
            sock.sendto(payload, (target_host, target_port))
            sent += 1
            if do_ioc and current_mode == "retro":
                if retro_delay_ms > 0:
                    time.sleep(retro_delay_ms / 1000.0)
                post_ioc(api_base, dst_ip, source_name, confidence, note)
                ioc_posts += 1
        except Exception:
            ioc_post_fail += 1

        now2 = time.time()
        if (now2 - last_stats) >= stats_every_sec:
            elapsed = max(now2 - t0, 1e-6)
            print(f"[loadgen] sent={sent} ioc_posts={ioc_posts} ioc_post_fail={ioc_post_fail} eps_avg={sent/elapsed:.1f}")
            last_stats = now2

        sleep_for = interval - (time.time() - now)
        if sleep_for > 0:
            time.sleep(sleep_for)

    print(f"[loadgen] done sent={sent} ioc_posts={ioc_posts} ioc_post_fail={ioc_post_fail}")


if __name__ == "__main__":
    main()
