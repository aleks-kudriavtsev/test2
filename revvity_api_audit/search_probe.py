#!/usr/bin/env python3
from __future__ import annotations

import hashlib
import json
import time
from pathlib import Path

import requests

OUT = Path("revvity_api_audit/results")
OUT.mkdir(parents=True, exist_ok=True)

HEADERS = {
    "User-Agent": "Mozilla/5.0 (compatible; Revvity-eIFU-audit/1.1; research; low-rate read-only)",
    "Accept": "application/json,text/plain,*/*",
    "Content-Type": "application/json",
    "Origin": "https://docs.revvity.com",
    "Referer": "https://docs.revvity.com/",
}

payload = {
    "globalFilter": "",
    "columnFilters": [],
    "batchDocumentLanguageFilters": [],
    "batchDocumentCountryFilters": [],
    "page": 1,
    "pageSize": 5,
    "sorting": [],
}

requests_to_make = [
    ("GET", "https://docs.revvity.com/.auth/me", None),
    ("POST", "https://docs.revvity.com/api/eifu/search", payload),
    ("POST", "https://eifu2-prod-api.azurewebsites.net/api/eifu/search", payload),
]

results = []
with requests.Session() as session:
    session.headers.update(HEADERS)
    for method, url, request_json in requests_to_make:
        rec = {"url": url, "method": method, "request_json": request_json}
        try:
            response = session.request(method, url, json=request_json, timeout=30, allow_redirects=True)
            body = response.content
            rec.update({
                "status": response.status_code,
                "final_url": response.url,
                "history": [{"status": h.status_code, "url": h.url, "location": h.headers.get("location")} for h in response.history],
                "headers": dict(response.headers),
                "content_type": response.headers.get("content-type"),
                "bytes": len(body),
                "sha256": hashlib.sha256(body).hexdigest(),
                "text": body.decode(response.encoding or "utf-8", errors="replace"),
            })
            try:
                rec["json"] = response.json()
            except Exception:
                pass
        except Exception as exc:
            rec["error"] = f"{type(exc).__name__}: {exc}"
        results.append(rec)
        time.sleep(0.5)

(OUT / "search_probe.json").write_text(json.dumps(results, ensure_ascii=False, indent=2), encoding="utf-8")
for rec in results:
    print(rec.get("method"), rec.get("status", "ERR"), rec.get("bytes", ""), rec.get("content_type", ""), rec.get("final_url", ""), rec.get("error", ""))
