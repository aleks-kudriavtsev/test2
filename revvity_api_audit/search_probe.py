#!/usr/bin/env python3
from __future__ import annotations

import hashlib
import json
from pathlib import Path

import requests

OUT = Path("revvity_api_audit/results")
OUT.mkdir(parents=True, exist_ok=True)
URL = "https://eifu2-prod-api.azurewebsites.net/api/eifu/search"
HEADERS = {
    "User-Agent": "Mozilla/5.0 (compatible; Revvity-eIFU-audit/1.0; research; one read-only request)",
    "Accept": "application/json,text/plain,*/*",
    "Content-Type": "application/json",
    "Origin": "https://docs.revvity.com",
    "Referer": "https://docs.revvity.com/",
}

payloads = [
    {
        "globalFilter": "",
        "columnFilters": [],
        "batchDocumentLanguageFilters": [],
        "batchDocumentCountryFilters": [],
        "page": 1,
        "pageSize": 5,
        "sorting": [],
    },
    {},
]

results = []
with requests.Session() as session:
    session.headers.update(HEADERS)
    for payload in payloads:
        rec = {"url": URL, "method": "POST", "request_json": payload}
        try:
            response = session.post(URL, json=payload, timeout=30, allow_redirects=True)
            body = response.content
            rec.update({
                "status": response.status_code,
                "final_url": response.url,
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

(OUT / "search_probe.json").write_text(json.dumps(results, ensure_ascii=False, indent=2), encoding="utf-8")
for rec in results:
    print(rec.get("status", "ERR"), rec.get("bytes", ""), rec.get("content_type", ""), rec.get("error", ""))
