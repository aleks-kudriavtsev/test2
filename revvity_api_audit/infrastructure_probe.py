#!/usr/bin/env python3
from __future__ import annotations

import json
import socket
from pathlib import Path

import requests

OUT = Path("revvity_api_audit/results")
OUT.mkdir(parents=True, exist_ok=True)
HEADERS = {"User-Agent": "Mozilla/5.0 (compatible; Revvity-eIFU-passive-audit/1.0)"}

result: dict[str, object] = {}

# Passive certificate-transparency lookup; keep only names plausibly related to document/eIFU services.
try:
    response = requests.get("https://crt.sh/", params={"q": "%.revvity.com", "output": "json"}, headers=HEADERS, timeout=90)
    ct = {"status": response.status_code, "bytes": len(response.content)}
    if response.status_code == 200:
        rows = response.json()
        names = set()
        for row in rows:
            for field in ("name_value", "common_name"):
                value = row.get(field)
                if isinstance(value, str):
                    for name in value.splitlines():
                        name = name.strip().lower().lstrip("*.")
                        if name.endswith(".revvity.com"):
                            names.add(name)
        ct["relevant_names"] = sorted(n for n in names if any(x in n for x in ("eifu", "doc", "manual", "resource", "ifu")))
        ct["all_names_count"] = len(names)
    else:
        ct["body"] = response.text[:3000]
    result["certificate_transparency"] = ct
except Exception as exc:
    result["certificate_transparency"] = {"error": f"{type(exc).__name__}: {exc}"}

# Conventional site metadata which can legitimately expose indexed deep links.
metadata = []
for url in [
    "https://docs.revvity.com/robots.txt",
    "https://docs.revvity.com/sitemap.xml",
    "https://docs.revvity.com/sitemap_index.xml",
    "https://www.revvity.com/robots.txt",
    "https://www.revvity.com/sitemap.xml",
    "https://www.revvity.com/sitemap_index.xml",
]:
    entry = {"url": url}
    try:
        response = requests.get(url, headers=HEADERS, timeout=45, allow_redirects=True)
        entry.update(status=response.status_code, final_url=response.url, content_type=response.headers.get("content-type"), bytes=len(response.content), text=response.text[:2_000_000])
    except Exception as exc:
        entry["error"] = f"{type(exc).__name__}: {exc}"
    metadata.append(entry)
result["site_metadata"] = metadata

# DNS address resolution only; no port scanning.
dns = {}
for host in ["docs.revvity.com", "resources.revvity.com", "eifu2-prod-api.azurewebsites.net"]:
    try:
        dns[host] = sorted({item[4][0] for item in socket.getaddrinfo(host, 443, type=socket.SOCK_STREAM)})
    except Exception as exc:
        dns[host] = {"error": f"{type(exc).__name__}: {exc}"}
result["dns_addresses"] = dns

(OUT / "infrastructure_probe.json").write_text(json.dumps(result, ensure_ascii=False, indent=2), encoding="utf-8")
print(json.dumps(result, ensure_ascii=False, indent=2)[:20000])
