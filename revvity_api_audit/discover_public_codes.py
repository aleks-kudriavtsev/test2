#!/usr/bin/env python3
from __future__ import annotations

import json
import re
import time
from pathlib import Path
from urllib.parse import urlparse

import requests

OUT = Path("revvity_api_audit/results")
OUT.mkdir(parents=True, exist_ok=True)
CODE_RE = re.compile(r"^/qr/([A-Za-z0-9]{6})/?$")
HEADERS = {
    "User-Agent": "Mozilla/5.0 (compatible; Revvity-eIFU-public-index-audit/1.0; low-rate research)",
    "Accept": "application/json,text/plain,*/*",
}

session = requests.Session()
session.headers.update(HEADERS)
raw_sources: dict[str, object] = {}
candidates: dict[str, set[str]] = {}


def add_url(url: str, source: str) -> None:
    try:
        parsed = urlparse(url)
        if parsed.hostname and parsed.hostname.lower() != "docs.revvity.com":
            return
        match = CODE_RE.match(parsed.path)
        if match:
            code = match.group(1).upper()
            candidates.setdefault(code, set()).add(source)
    except Exception:
        return


def safe_get(url: str, *, params: dict | None = None, timeout: int = 60):
    try:
        response = session.get(url, params=params, timeout=timeout)
        return response
    except Exception as exc:
        return exc

# Common Crawl URL index: recent collections first, then all available collections.
coll_response = safe_get("https://index.commoncrawl.org/collinfo.json")
collections = []
if isinstance(coll_response, requests.Response):
    try:
        collections = coll_response.json()
    except Exception:
        raw_sources["commoncrawl_collinfo_error"] = coll_response.text[:2000]
else:
    raw_sources["commoncrawl_collinfo_exception"] = repr(coll_response)

cc_records = []
for coll in collections:
    coll_id = coll.get("id")
    api = coll.get("cdx-api") or (f"https://index.commoncrawl.org/{coll_id}-index" if coll_id else None)
    if not api:
        continue
    # eIFU v2 is recent; 2024 onward is enough to catch its public URLs without hammering decades of indexes.
    year_match = re.search(r"CC-MAIN-(\d{4})", str(coll_id))
    if year_match and int(year_match.group(1)) < 2024:
        continue
    response = safe_get(api, params={
        "url": "docs.revvity.com/qr/",
        "matchType": "prefix",
        "output": "json",
        "filter": "status:200",
        "collapse": "urlkey",
    })
    entry = {"collection": coll_id, "api": api}
    if isinstance(response, requests.Response):
        entry.update(status=response.status_code, bytes=len(response.content))
        urls = []
        if response.status_code == 200:
            for line in response.text.splitlines():
                try:
                    item = json.loads(line)
                except Exception:
                    continue
                url = item.get("url")
                if url:
                    urls.append(url)
                    add_url(url, f"Common Crawl {coll_id}")
        else:
            entry["body"] = response.text[:1000]
        entry["urls"] = urls
    else:
        entry["error"] = repr(response)
    cc_records.append(entry)
    time.sleep(0.35)
raw_sources["commoncrawl"] = cc_records

# Internet Archive CDX index.
wayback = safe_get("https://web.archive.org/cdx/search/cdx", params={
    "url": "docs.revvity.com/qr/*",
    "output": "json",
    "filter": "statuscode:200",
    "fl": "original,timestamp,statuscode,digest",
    "collapse": "urlkey",
})
if isinstance(wayback, requests.Response):
    wb = {"status": wayback.status_code, "bytes": len(wayback.content)}
    try:
        rows = wayback.json()
        wb["rows"] = rows
        for row in rows[1:] if isinstance(rows, list) else []:
            if row:
                add_url(str(row[0]), "Internet Archive CDX")
    except Exception:
        wb["body"] = wayback.text[:5000]
    raw_sources["wayback"] = wb
else:
    raw_sources["wayback"] = {"error": repr(wayback)}

# URLScan public search API.
urlscan_queries = [
    "domain:docs.revvity.com AND filename:\"/qr/\"",
    "domain:docs.revvity.com AND page.url:*\\/qr\\/*",
]
urlscan_results = []
for query in urlscan_queries:
    response = safe_get("https://urlscan.io/api/v1/search/", params={"q": query, "size": 100})
    entry = {"query": query}
    if isinstance(response, requests.Response):
        entry.update(status=response.status_code, bytes=len(response.content))
        try:
            data = response.json()
            entry["data"] = data
            for result in data.get("results", []):
                for key in ("page", "task"):
                    obj = result.get(key) or {}
                    for field in ("url", "domain"):
                        value = obj.get(field)
                        if isinstance(value, str) and value.startswith("http"):
                            add_url(value, "urlscan.io")
        except Exception:
            entry["body"] = response.text[:5000]
    else:
        entry["error"] = repr(response)
    urlscan_results.append(entry)
    time.sleep(1)
raw_sources["urlscan"] = urlscan_results

# AlienVault OTX passive URL list, if available without a key.
otx_pages = []
for page in range(1, 6):
    response = safe_get(
        "https://otx.alienvault.com/api/v1/indicators/hostname/docs.revvity.com/url_list",
        params={"limit": 500, "page": page},
    )
    entry = {"page": page}
    if isinstance(response, requests.Response):
        entry.update(status=response.status_code, bytes=len(response.content))
        try:
            data = response.json()
            entry["data"] = data
            for item in data.get("url_list", []):
                url = item.get("url") if isinstance(item, dict) else None
                if url:
                    add_url(url, "AlienVault OTX")
            if not data.get("has_next"):
                otx_pages.append(entry)
                break
        except Exception:
            entry["body"] = response.text[:5000]
    else:
        entry["error"] = repr(response)
    otx_pages.append(entry)
    time.sleep(0.5)
raw_sources["otx"] = otx_pages

# Include the already evidenced codes so the validation artifact is self-contained.
known = ["TKZA0K", "JSHFOD", "P8EYZE", "ATF1Q7", "O0H3JP", "BQRXAC", "GEOGPN", "R08LT5", "QJ7OZK", "6ECJFY", "5QRCC0", "A70WRK"]
for code in known:
    candidates.setdefault(code, set()).add("Existing evidence set")

# Validate only passively discovered/known candidates; this is not a token-space scan.
validated = []
for code in sorted(candidates):
    url = f"https://eifu2-prod-api.azurewebsites.net/api/eifu/kit/id/{code}"
    rec = {"code": code, "url": url, "sources": sorted(candidates[code])}
    try:
        response = session.get(url, timeout=45)
        rec.update(status=response.status_code, content_type=response.headers.get("content-type"), bytes=len(response.content))
        if response.status_code == 200:
            try:
                payload = response.json()
                rec["payload"] = payload
            except Exception:
                rec["body"] = response.text[:5000]
        else:
            rec["body"] = response.text[:1000]
    except Exception as exc:
        rec["error"] = f"{type(exc).__name__}: {exc}"
    validated.append(rec)
    time.sleep(0.35)

(OUT / "public_discovery_raw.json").write_text(json.dumps(raw_sources, ensure_ascii=False, indent=2), encoding="utf-8")
(OUT / "public_codes_validated.json").write_text(json.dumps(validated, ensure_ascii=False, indent=2), encoding="utf-8")

summary = []
for rec in validated:
    data = (rec.get("payload") or {}).get("data") or {}
    summary.append({
        "code": rec["code"],
        "status": rec.get("status"),
        "api_id": data.get("id"),
        "materialNumber": data.get("materialNumber"),
        "materialName": data.get("materialName"),
        "batchId": data.get("batchId"),
        "combinationLot": data.get("combinationLot"),
        "state": data.get("state"),
        "created": data.get("created"),
        "expires": data.get("expires"),
        "sources": rec["sources"],
    })
(OUT / "public_codes_summary.json").write_text(json.dumps(summary, ensure_ascii=False, indent=2), encoding="utf-8")
print(json.dumps(summary, ensure_ascii=False, indent=2))
