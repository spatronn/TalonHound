#!/usr/bin/env python3
import json
import os
import random
import socket
import time
import urllib.parse
import urllib.request
from datetime import datetime, timezone


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
        if ip.startswith(("10.", "192.168.", "127.")):
            continue
        if a == 172 and 16 <= b <= 31:
            continue
        return ip


def rand_private_ip():
    return f"10.{random.randint(1,254)}.{random.randint(1,254)}.{random.randint(1,254)}"


def rand_dst_ip_from_target_subnet():
    return f"213.14.158.{random.randint(1, 254)}"


def utc_parts():
    now = datetime.now(timezone.utc)
    return now.strftime("%Y-%m-%d"), now.strftime("%H:%M:%S")


def rand_sha256():
    return "".join(random.choice("0123456789abcdef") for _ in range(64))


def post_ioc_ip(api_base, ip, source_name, confidence, note):
    url = f"{api_base.rstrip('/')}/api/ioc/ip"
    payload = {"ip": ip, "source_name": source_name, "confidence": str(confidence), "note": note}
    data = json.dumps(payload).encode("utf-8")
    headers = {"Content-Type": "application/json"}
    ingest = os.getenv("API_INGEST_TOKEN", "").strip() or os.getenv("API_BEARER_TOKEN", "").strip()
    if ingest:
        headers["X-Api-Ingest-Token"] = ingest
    req = urllib.request.Request(url, data=data, headers=headers, method="POST")
    with urllib.request.urlopen(req, timeout=5) as resp:
        return resp.status


def build_firewall_log(src_ip, dst_ip, dst_port):
    d, t = utc_parts()
    return (
        f'date={d} time={t} type="traffic" subtype="forward" level="notice" '
        f'srcip={src_ip} srcport={random.randint(1024,65535)} dstip={dst_ip} dstport={dst_port} '
        f'proto=6 action="accept" service="tcp/{dst_port}" sessionid={random.randint(100000,999999)} '
        f'sentbyte={random.randint(400,9000)} rcvdbyte={random.randint(200,7000)}'
    )


def build_dns_log(client_ip, domain, response_ip):
    d, t = utc_parts()
    return (
        f"date={d} time={t} type=dns client_ip={client_ip} "
        f"query={domain} query_type=A response_ip={response_ip}"
    )


def build_proxy_log(src_ip, url):
    d, t = utc_parts()
    return (
        f"date={d} time={t} type=proxy srcip={src_ip} "
        f"url={url} method={random.choice(['GET','POST'])} status={random.choice([200,301,302,403,404])} "
        f"bytes={random.randint(512,8192)}"
    )


def build_endpoint_log(host, filename, sha256):
    d, t = utc_parts()
    return (
        f"date={d} time={t} type=endpoint host={host} file={filename} "
        f"sha256={sha256} action={random.choice(['executed','blocked','quarantined'])}"
    )


def main():
    enabled = os.getenv("ENABLED", "0") == "1"
    target_host = os.getenv("SYSLOG_HOST", "syslog-receiver")
    target_port = env_int("SYSLOG_PORT", 514)
    udp_ingest_key = os.getenv("SYSLOG_UDP_SHARED_SECRET", "").strip()
    api_base = os.getenv("IOC_API_BASE", "http://backend:3000")

    eps = max(env_int("EPS", 200), 1)
    duration_seconds = env_int("DURATION_SECONDS", 0)
    stats_every_sec = max(env_int("STATS_EVERY_SEC", 10), 1)
    source_name = os.getenv("IOC_SOURCE_NAME", "loadgen-advanced")
    confidence = os.getenv("IOC_CONFIDENCE", "90")
    note = os.getenv("IOC_NOTE", "advanced scenario loadgen")
    ioc_insert_ratio = max(0.0, min(env_float("IOC_INSERT_RATIO", 0.05), 1.0))  # target noisy-realistic ratio
    benign_ratio = max(0.0, min(env_float("BENIGN_RATIO", 0.95), 1.0))

    scenario = os.getenv("SCENARIO", "mixed").strip().upper()

    print(f"[loadgen] enabled={enabled} scenario={scenario} eps={eps} duration={duration_seconds} benign_ratio={benign_ratio} ioc_ratio={ioc_insert_ratio}")
    if not enabled:
        print("[loadgen] ENABLED=0 (idle)")
        while True:
            time.sleep(30)

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    interval = 1.0 / eps
    t0 = time.time()
    last_stats = t0

    sent = 0
    ioc_posts = 0
    ioc_post_fail = 0
    by_type = {"firewall": 0, "dns": 0, "proxy": 0, "endpoint": 0}
    by_class = {"benign": 0, "ioc": 0}

    # Realism pools/correlation
    malicious_domain_to_ip = {
        "cdn-login-security.com": "45.9.148.77",
        "auth-checkpoint365.net": "185.234.219.41",
        "malicious-domain.com": "5.6.7.8",
        "update-microsoft-secure.net": "91.214.124.22",
    }
    benign_domain_to_ip = {
        "google.com": "142.250.186.14",
        "microsoft.com": "20.112.52.29",
        "cloudflare.com": "104.16.132.229",
        "github.com": "140.82.121.4",
        "wikipedia.org": "208.80.154.224",
    }
    domain_paths = ["/login", "/admin", "/panel", "/index.php", "/oauth/callback", "/invoice/view", "/search", "/docs", "/api/v1/ping"]
    endpoint_files = ["invoice.exe", "update.dll", "vpn_helper.exe", "chrome_updater.tmp"]
    hosts = [f"host-{i:02d}" for i in range(1, 25)]
    shared_hashes = [rand_sha256() for _ in range(8)]

    scenario_map = {
        "PORT_SCAN": ["firewall"],
        "C2_BEACON": ["firewall", "dns"],
        "MALWARE_SPREAD": ["endpoint", "proxy", "dns"],
        "PHISHING": ["proxy", "dns"],
    }

    while True:
        start = time.time()
        if duration_seconds > 0 and (start - t0) >= duration_seconds:
            break

        is_benign = random.random() < benign_ratio
        chosen = "BENIGN" if is_benign else scenario
        if not is_benign and scenario == "MIXED":
            chosen = random.choice(list(scenario_map.keys()))

        if is_benign:
            log_types = random.choices(
                population=[["dns", "proxy"], ["proxy"], ["dns"], ["firewall"], ["dns", "proxy", "firewall"]],
                weights=[40, 20, 20, 10, 10],
                k=1,
            )[0]
            domain = random.choice(list(benign_domain_to_ip.keys()))
            resolved_ip = benign_domain_to_ip[domain]
            sha256 = rand_sha256()
        else:
            log_types = scenario_map.get(chosen, ["firewall", "dns", "proxy", "endpoint"])
            domain = random.choice(list(malicious_domain_to_ip.keys()))
            resolved_ip = malicious_domain_to_ip[domain]
            sha256 = random.choice(shared_hashes)

        src_ip = rand_private_ip()
        url = f"http://{domain}{random.choice(domain_paths)}"
        host = random.choice(hosts)
        file_name = random.choice(endpoint_files)

        records = []
        if "dns" in log_types:
            records.append(("dns", build_dns_log(src_ip, domain, resolved_ip)))
        if "proxy" in log_types:
            records.append(("proxy", build_proxy_log(src_ip, url)))
        if "firewall" in log_types:
            records.append(("firewall", build_firewall_log(src_ip, resolved_ip, random.choice([80,443,8080]))))
        if "endpoint" in log_types:
            records.append(("endpoint", build_endpoint_log(host, file_name, sha256)))

        # IOC pipeline hinting: only part of events should hit IOCs
        do_ioc = (not is_benign) and (random.random() < min(1.0, ioc_insert_ratio / max(1e-6, (1.0 - benign_ratio))))
        if do_ioc:
            try:
                post_ioc_ip(api_base, resolved_ip, source_name, confidence, f"{note} scenario={chosen} domain={domain}")
                ioc_posts += 1
            except Exception:
                ioc_post_fail += 1

        for typ, msg in records:
            payload = msg.encode("utf-8")
            if udp_ingest_key:
                payload = f"{udp_ingest_key}|".encode("utf-8") + payload
            sock.sendto(payload, (target_host, target_port))
            by_type[typ] += 1
            sent += 1
        by_class["benign" if is_benign else "ioc"] += len(records)

        now = time.time()
        if (now - last_stats) >= stats_every_sec:
            elapsed = max(now - t0, 1e-6)
            total_cls = max(1, by_class['benign'] + by_class['ioc'])
            benign_pct = (by_class['benign'] * 100.0) / total_cls
            ioc_pct = (by_class['ioc'] * 100.0) / total_cls
            print(
                f"[loadgen] sent={sent} ioc_posts={ioc_posts} fail={ioc_post_fail} eps_avg={sent/elapsed:.1f} "
                f"fw={by_type['firewall']} dns={by_type['dns']} proxy={by_type['proxy']} endpoint={by_type['endpoint']} "
                f"benign={benign_pct:.1f}% ioc={ioc_pct:.1f}%"
            )
            last_stats = now

        sleep_for = interval - (time.time() - start)
        if sleep_for > 0:
            time.sleep(sleep_for)

    print(f"[loadgen] done sent={sent} by_type={by_type} ioc_posts={ioc_posts} fail={ioc_post_fail}")


if __name__ == "__main__":
    main()
