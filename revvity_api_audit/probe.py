#!/usr/bin/env python3
from __future__ import annotations

import hashlib
import json
import re
import time
from pathlib import Path
from urllib.parse import urljoin, urlparse

import requests

OUT = Path("revvity_api_audit/results")
OUT.mkdir(parents=True, exist_ok=True)

DOCS = "https://docs.revvity.com/"
API = "https://eifu2-prod-api.azurewebsites.net"
KNOWN_CODE = "P8EYZE"
KNOWN_NUMERIC_ID = "1111"

HEADERS = {
    "User-Agent": "Mozilla/5.0 (compatible; Revvity-eIFU-audit/1.1; research; low-rate)",
    "Accept": "application/json,text/plain,text/html,application/javascript,*/*",
    "Referer": f"https://docs.revvity.com/qr/{KNOWN_CODE}",
}

session = requests.Session()
session.headers.update(HEADERS)


def request_raw(url: str, method: str = "GET", timeout: int = 30):
    return session.request(method, url, timeout=timeout, allow_redirects=True)


def fetch(url: str, method: str = "GET", timeout: int = 30, text_limit: int = 500_000) -> dict:
    rec: dict = {"url": url, "method": method}
    try:
        r = request_raw(url, method=method, timeout=timeout)
        body = r.content
        rec.update(
            status=r.status_code,
            final_url=r.url,
            history=[{"status": h.status_code, "url": h.url, "location": h.headers.get("location")} for h in r.history],
            headers={k: v for k, v in r.headers.items()},
            content_type=r.headers.get("content-type"),
            bytes=len(body),
            sha256=hashlib.sha256(body).hexdigest(),
            text=body[:text_limit].decode(r.encoding or "utf-8", errors="replace"),
        )
    except Exception as exc:
        rec["error"] = f"{type(exc).__name__}: {exc}"
    return rec


records: list[dict] = []

# 1. Fetch the public SPA and every JS/CSS asset in full.
docs = fetch(DOCS)
records.append(docs)
(OUT / "docs_index.html").write_text(docs.get("text", ""), encoding="utf-8")

asset_urls: list[str] = []
if docs.get("status") == 200:
    for value in re.findall(r'''(?:src|href)=["']([^"']+)["']''', docs.get("text", ""), flags=re.I):
        absolute = urljoin(DOCS, value)
        if any(absolute.lower().split("?", 1)[0].endswith(ext) for ext in (".js", ".css")):
            asset_urls.append(absolute)

asset_metadata: list[dict] = []
absolute_urls: set[str] = set()
quoted_candidates: set[str] = set()
contexts: list[dict] = []
discovered_api_paths: set[str] = set()

for index, asset_url in enumerate(sorted(set(asset_urls)), start=1):
    try:
        r = request_raw(asset_url)
        body = r.content
        suffix = Path(urlparse(asset_url).path).suffix or ".bin"
        asset_path = OUT / f"asset_{index:02d}{suffix}"
        asset_path.write_bytes(body)
        text = body.decode(r.encoding or "utf-8", errors="replace")
        asset_metadata.append({
            "url": asset_url,
            "status": r.status_code,
            "content_type": r.headers.get("content-type"),
            "bytes": len(body),
            "sha256": hashlib.sha256(body).hexdigest(),
            "saved_as": asset_path.name,
        })

        for value in re.findall(r'''https?://[^"'`\\\s]+''', text):
            absolute_urls.add(value.rstrip(")]};,"))
        for value in re.findall(r'''["'`]([^"'`]{1,500})["'`]''', text):
            if any(token in value.lower() for token in ("/api/", "eifu", "kit/id", "batchid", "combinationlot", "reserve")):
                quoted_candidates.add(value)
        for value in re.findall(r'''/api/[A-Za-z0-9_./?=&{}:$+-]+''', text):
            discovered_api_paths.add(value.rstrip(".,);]}"))

        for pattern in (r"eifu2-prod-api", r"/api/eifu", r"kit/id", r"reserveEifuCode", r"batchId", r"combinationLot", r"reserve"):
            for match in re.finditer(pattern, text, flags=re.I):
                lo = max(0, match.start() - 500)
                hi = min(len(text), match.end() + 1000)
                contexts.append({"asset": asset_url, "pattern": pattern, "offset": match.start(), "text": text[lo:hi]})

        # Fetch source map when explicitly referenced by the bundle.
        map_match = re.search(r"//# sourceMappingURL=([^\s]+)", text[-1000:])
        if map_match:
            map_url = urljoin(asset_url, map_match.group(1))
            mr = request_raw(map_url)
            map_path = OUT / f"asset_{index:02d}{suffix}.map"
            map_path.write_bytes(mr.content)
            asset_metadata.append({
                "url": map_url,
                "status": mr.status_code,
                "content_type": mr.headers.get("content-type"),
                "bytes": len(mr.content),
                "sha256": hashlib.sha256(mr.content).hexdigest(),
                "saved_as": map_path.name,
            })
    except Exception as exc:
        asset_metadata.append({"url": asset_url, "error": f"{type(exc).__name__}: {exc}"})

(OUT / "spa_analysis.json").write_text(json.dumps({
    "assets": asset_metadata,
    "absolute_urls": sorted(absolute_urls),
    "quoted_candidates": sorted(quoted_candidates),
    "discovered_api_paths": sorted(discovered_api_paths),
    "contexts": contexts,
}, ensure_ascii=False, indent=2), encoding="utf-8")

# 2. Probe a small, conventional, read-only route set. No token-space scan.
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
# Add only clearly extracted API paths from the public bundle.
for path in sorted(discovered_api_paths):
    if path.startswith("/api/") and "{" not in path and "$" not in path and len(path) < 300:
        paths.append(path)

seen: set[str] = set()
for path in paths:
    url = path if path.startswith("http") else API + path
    if url in seen:
        continue
    seen.add(url)
    records.append(fetch(url))
    time.sleep(0.25)

for path in ["/api/eifu/kit", "/api/eifu/kit/id/", f"/api/eifu/kit/id/{KNOWN_CODE}"]:
    records.append(fetch(API + path, method="OPTIONS"))
    time.sleep(0.25)

(OUT / "probe_results.json").write_text(json.dumps(records, ensure_ascii=False, indent=2), encoding="utf-8")

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
