#!/usr/bin/env python3
import csv
import json
import os
import re
from collections import Counter
from datetime import datetime
from zoneinfo import ZoneInfo
from urllib.request import urlopen, Request
import xml.etree.ElementTree as ET

RSS_URL = "https://www.milliyet.com.tr/rss/rssnew/sondakikarss.xml"
BASE_DIR = "/home/spatronn/.openclaw/workspace/reports/milliyet_haberler"
TZ = ZoneInfo("Europe/Istanbul")  # UTC+3


def fetch(url: str) -> str:
    req = Request(url, headers={"User-Agent": "Mozilla/5.0"})
    with urlopen(req, timeout=25) as r:
        return r.read().decode("utf-8", errors="replace")


def clean_html(text: str) -> str:
    text = re.sub(r"<[^>]+>", " ", text)
    text = re.sub(r"\s+", " ", text).strip()
    return text


def classify(title: str, desc: str):
    t = f"{title} {desc}".lower()
    tags = []

    def add(*xs):
        for x in xs:
            if x not in tags:
                tags.append(x)

    if any(k in t for k in ["dolar", "euro", "faiz", "enflasyon", "borsa", "ekonomi", "piyasa"]):
        add("Türkiye > Ekonomi", "Piyasalar")
    if any(k in t for k in ["cumhurbaşkanı", "kabine", "bakan", "meclis", "seçim", "parti"]):
        add("Türkiye > Siyaset")
    if any(k in t for k in ["mahkeme", "gözaltı", "tutuk", "adli", "savcı", "dava"]):
        add("Türkiye > Adliye")
    if any(k in t for k in ["kazada", "yaralı", "cinayet", "asayiş", "saldırı", "bıçak", "silah"]):
        add("Türkiye > Asayiş")
    if any(k in t for k in ["abd", "israil", "hamas", "iran", "ukrayna", "rusya", "meksika", "dünya", "yurt dışı"]):
        add("Yurt Dışı")
    if any(k in t for k in ["kartel", "savaş", "operasyon", "bomb", "güvenlik", "terör"]):
        add("Güvenlik/Çatışma")
    if any(k in t for k in ["fenerbahçe", "galatasaray", "beşiktaş", "trabzon", "maç", "spor", "skorer"]):
        add("Spor")
    if any(k in t for k in ["survivor", "magazin", "oyuncu", "şarkıcı", "cadde"]):
        add("Magazin")
    if any(k in t for k in ["hava", "kar", "fırtına", "deprem", "sel", "afet"]):
        add("Afet/Hava")

    if not tags:
        add("Genel")

    return tags


def extract_entities(text: str):
    # very lightweight proper-name style extraction
    candidates = re.findall(r"\b([A-ZÇĞİÖŞÜ][a-zçğıöşü]+(?:\s+[A-ZÇĞİÖŞÜ][a-zçğıöşü]+){0,2})\b", text)
    stop = {"Son Dakika", "Milliyet", "Türkiye", "Günlük Burç", "Haber"}
    out = []
    for c in candidates:
        if c in stop:
            continue
        if c not in out:
            out.append(c)
        if len(out) >= 12:
            break
    return out


def parse_rss(xml_text: str):
    root = ET.fromstring(xml_text)
    items = []
    for item in root.findall("./channel/item"):
        title = (item.findtext("title") or "").strip()
        desc_html = (item.findtext("description") or "").strip()
        link_el = item.find('{http://www.w3.org/2005/Atom}link')
        link = link_el.attrib.get('href', '') if link_el is not None else (item.findtext('link') or '')
        guid = (item.findtext("guid") or "").strip()
        pub_date = (item.findtext("pubDate") or "").strip()
        desc = clean_html(desc_html)
        tags = classify(title, desc)
        entities = extract_entities(f"{title} {desc}")
        items.append({
            "guid": guid,
            "title": title,
            "link": link,
            "pubDate": pub_date,
            "tags": tags,
            "entities": entities,
        })
    return items


def ensure_dir(p):
    os.makedirs(p, exist_ok=True)


def write_run_stat(day_dir: str, now: datetime, hm: str, status: str, msg: str = "", news_count: int = 0):
    ensure_dir(day_dir)
    p = os.path.join(day_dir, "run_status.csv")
    exists = os.path.exists(p)
    with open(p, "a", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        if not exists:
            w.writerow(["run_time_utc3", "slot", "status", "news_count", "message"])
        w.writerow([now.strftime("%Y-%m-%d %H:%M:%S"), hm, status, news_count, msg[:500]])


def main():
    now = datetime.now(TZ)
    day = now.strftime("%Y-%m-%d")
    hm = now.strftime("%H-%M")

    run_dir = os.path.join(BASE_DIR, day, hm)
    day_dir = os.path.join(BASE_DIR, day)
    ensure_dir(run_dir)

    try:
        raw = fetch(RSS_URL)
        items = parse_rss(raw)
    except Exception as e:
        err = f"{type(e).__name__}: {e}"
        with open(os.path.join(run_dir, "error.txt"), "w", encoding="utf-8") as f:
            f.write(err + "\n")
        write_run_stat(day_dir, now, hm, "FAIL", err, 0)
        print(f"FAIL {run_dir} {err}")
        return

    with open(os.path.join(run_dir, "raw_rss.xml"), "w", encoding="utf-8") as f:
        f.write(raw)

    with open(os.path.join(run_dir, "items.json"), "w", encoding="utf-8") as f:
        json.dump(items, f, ensure_ascii=False, indent=2)

    counter = Counter()
    for it in items:
        for tag in it["tags"]:
            counter[tag] += 1
    top10 = counter.most_common(10)

    summary_lines = [
        f"Zaman (UTC+3): {now.strftime('%Y-%m-%d %H:%M')}",
        f"Toplam haber: {len(items)}",
        "",
        "Top 10 Kategori:",
    ]
    for i, (k, v) in enumerate(top10, start=1):
        summary_lines.append(f"{i}. {k} ({v})")

    summary_lines.append("\nÖrnek Haberler:")
    for it in items[:15]:
        summary_lines.append(f"- {it['title']}")
        summary_lines.append(f"  Etiketler: {', '.join(it['tags'])}")
        if it['entities']:
            summary_lines.append(f"  Varlıklar: {', '.join(it['entities'])}")
        if it['link']:
            summary_lines.append(f"  Link: {it['link']}")

    with open(os.path.join(run_dir, "summary.txt"), "w", encoding="utf-8") as f:
        f.write("\n".join(summary_lines) + "\n")

    # append daily csv log
    ensure_dir(day_dir)
    csv_path = os.path.join(day_dir, "daily_log.csv")
    csv_exists = os.path.exists(csv_path)
    with open(csv_path, "a", newline="", encoding="utf-8") as cf:
        w = csv.writer(cf)
        if not csv_exists:
            w.writerow(["run_time_utc3", "guid", "title", "tags", "entities", "link"])
        for it in items:
            w.writerow([
                now.strftime("%Y-%m-%d %H:%M"),
                it["guid"],
                it["title"],
                " | ".join(it["tags"]),
                " | ".join(it["entities"]),
                it["link"],
            ])

    # daily aggregate report
    agg = Counter()
    unique_titles = []
    seen = set()
    with open(csv_path, "r", encoding="utf-8") as cf:
        r = csv.DictReader(cf)
        for row in r:
            for t in [x.strip() for x in row["tags"].split("|") if x.strip()]:
                agg[t] += 1
            if row["title"] not in seen:
                seen.add(row["title"])
                unique_titles.append(row["title"])

    # read 15-minute summaries for daily narrative
    run_summaries = []
    for name in sorted(os.listdir(day_dir)):
        p = os.path.join(day_dir, name, "summary.txt")
        if re.match(r"^\d{2}-\d{2}$", name) and os.path.isfile(p):
            try:
                with open(p, "r", encoding="utf-8") as sf:
                    run_summaries.append((name, sf.read()))
            except Exception:
                pass

    report = [
        f"# Milliyet Günlük Rapor ({day})",
        f"Güncelleme zamanı (UTC+3): {now.strftime('%Y-%m-%d %H:%M')}",
        f"Toplanan 15 dk slot sayısı: {len(run_summaries)}",
        "",
        "## Top 10 Kategori (gün boyu birikimli)",
    ]
    for i, (k, v) in enumerate(agg.most_common(10), start=1):
        report.append(f"{i}. {k} ({v})")

    report.append("\n## Günlük Kısa Özet")
    if agg:
        top = ", ".join([f"{k} ({v})" for k, v in agg.most_common(3)])
        report.append(f"Bugün öne çıkan başlık kümeleri: {top}.")
    report.append(f"Toplam benzersiz başlık: {len(unique_titles)}")

    report.append("\n## 15 Dakikalık Özetlerden Beslenen Zaman Akışı")
    for slot, text in run_summaries[-24:]:  # last 6 hours (24 x 15dk)
        first_line = ""
        for ln in text.splitlines():
            if ln.startswith("Toplam haber:"):
                first_line = ln
                break
        top_line = ""
        lines = text.splitlines()
        for i, ln in enumerate(lines):
            if ln.strip() == "Top 10 Kategori:" and i + 1 < len(lines):
                top_line = lines[i + 1].strip()
                break
        report.append(f"- {slot}: {first_line} | {top_line}")

    report.append("\n## Son 20 Benzersiz Başlık")
    for t in unique_titles[-20:]:
        report.append(f"- {t}")

    # run statistics + health summary
    write_run_stat(day_dir, now, hm, "OK", "", len(items))

    status_csv = os.path.join(day_dir, "run_status.csv")
    ok = fail = 0
    last_fail = ""
    if os.path.exists(status_csv):
        with open(status_csv, "r", encoding="utf-8") as sf:
            rr = csv.DictReader(sf)
            for row in rr:
                if row.get("status") == "OK":
                    ok += 1
                else:
                    fail += 1
                    last_fail = f"{row.get('run_time_utc3')} {row.get('message')}"

    report.append("\n## Job Sağlık İstatistiği")
    report.append(f"- Başarılı run: {ok}")
    report.append(f"- Başarısız run: {fail}")
    if last_fail:
        report.append(f"- Son hata: {last_fail}")

    with open(os.path.join(day_dir, "daily_report.md"), "w", encoding="utf-8") as f:
        f.write("\n".join(report) + "\n")

    print(f"OK {run_dir}")


if __name__ == "__main__":
    main()
