#!/usr/bin/env python3
from __future__ import annotations

import hashlib
import json
import re
import time
from pathlib import Path
from urllib.parse import urljoin

import requests

OUT = Path("revvity_api_audit/results")
OUT.mkdir(parents=True, exist_ok=True)

DOCS = "https://docs.revvity.com/"
API = "https://eifu2-prod-api.azurewebsites.net"
KNOWN_CODE = "P8EYZE"
KNOWN_NUMERIC_ID = "1111"

HEADERS = {
    "User-Agent": "Mozilla/5.0 (compatible; Revvity-eIFU-audit/1.0; research; low-rate)",
    "Accept": "application/json,text/plain,text/html,application/javascript,*/*",
    "Referer": f"https://docs.revvity.com/qr/{KNOWN_CODE}",
}

session = requests.Session()
session.headers.update(HEADERS)


def fetch(url: str, method: str = "GET", timeout: int = 30) -> dict:
    rec: dict = {"url": url, "method": method}
    try:
        r = session.request(method, url, timeout=timeout, allow_redirects=True)
        body = r.content
        rec.update(
            status=r.status_code,
            final_url=r.url,
            history=[{"status": h.status_code, "url": h.url, "location": h.headers.get("location")} for h in r.history],
            headers={k: v for k, v in r.headers.items()},
            content_type=r.headers.get("content-type"),
            bytes=len(body),
            sha256=hashlib.sha256(body).hexdigest(),
            text=body[:500000].decode(r.encoding or "utf-8", errors="replace"),
        )
    except Exception as exc:
        rec["error"] = f"{type(exc).__name__}: {exc}"
    return rec


records: list[dict] = []

# 1. Fetch public SPA and its static assets, then extract API route strings.
docs = fetch(DOCS)
records.append(docs)
asset_urls: list[str] = []
if docs.get("status") == 200:
    html = docs.get("text", "")
    for value in re.findall(r'''(?:src|href)=["']([^"']+)["']''', html, flags=re.I):
        absolute = urljoin(DOCS, value)
        if any(absolute.lower().split("?", 1)[0].endswith(ext) for ext in (".js", ".css")):
            asset_urls.append(absolute)

asset_records: list[dict] = []
route_strings: set[str] = set()
absolute_urls: set[str] = set()
for asset_url in sorted(set(asset_urls)):
    rec = fetch(asset_url)
    asset_records.append(rec)
    text = rec.get("text", "")
    for value in re.findall(r'''https?://[^"'`\\\s]+''', text):
        absolute_urls.add(value.rstrip(")]};,"))
    for value in re.findall(r'''["'`](/api/[A-Za-z0-9_./?=&{}:-]+)["'`]''', text):
        route_strings.add(value)
    # Broader fragments around eifu/kit, useful when minification concatenates strings.
    for match in re.finditer(r"eifu|/api/|reserveEifuCode|batchId|combinationLot", text, flags=re.I):
        lo = max(0, match.start() - 250)
        hi = min(len(text), match.end() + 450)
        route_strings.add("CONTEXT: " + text[lo:hi])

(OUT / "spa_assets.json").write_text(
    json.dumps({"assets": asset_records, "api_route_strings": sorted(route_strings), "absolute_urls": sorted(absolute_urls)}, ensure_ascii=False, indent=2),
    encoding="utf-8",
)

# 2. Probe only a small set of conventional read-only routes. No code-space brute force.
paths = [
    "/",
    "/api/eifu/kit/id/",
    f"/api/eifu/kit/id/{KNOWN_CODE}",
    "/api/eifu/kit",
    "/api/eifu/kit/",
    f"/api/eifu/kit/{KNOWN_NUMERIC_ID}",
    "/api/eifu/kits",
    "/api/eifu/kits/",
    "/api/eifu/kit/all",
    "/api/eifu/kit/list",
    "/api/eifu/kit/search",
    "/api/eifu/kit/count",
    "/api/eifu/batch",
    "/api/eifu/batches",
    "/swagger",
    "/swagger/",
    "/swagger/index.html",
    "/swagger/v1/swagger.json",
    "/swagger/docs/v1",
    "/openapi.json",
    "/api-docs",
    "/api-docs/",
    "/.well-known/openapi.json",
]
for path in paths:
    records.append(fetch(API + path))
    time.sleep(0.25)

# OPTIONS may reveal allowed methods/CORS without modifying anything.
for path in ["/api/eifu/kit", "/api/eifu/kit/id/", f"/api/eifu/kit/id/{KNOWN_CODE}"]:
    records.append(fetch(API + path, method="OPTIONS"))
    time.sleep(0.25)

(OUT / "probe_results.json").write_text(json.dumps(records, ensure_ascii=False, indent=2), encoding="utf-8")

# Compact human-readable summary.
lines = ["method\tstatus\tbytes\tcontent-type\turl\tfinal-url/error"]
for rec in records:
    lines.append("\t".join([
        str(rec.get("method", "")),
        str(rec.get("status", "ERR")),
        str(rec.get("bytes", "")),
        str(rec.get("content_type", "")),
        str(rec.get("url", "")),
        str(rec.get("final_url") or rec.get("error") or ""),
    ]))
(OUT / "summary.tsv").write_text("\n".join(lines) + "\n", encoding="utf-8")
print("\n".join(lines))
