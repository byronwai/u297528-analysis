#!/usr/bin/env python3
"""Fetch VirusTotal results for all submitted files"""

import requests
import json
import time
import os

VT_API_KEY = "d3a82556c8c402e6d13fa98bfa01f009dc660b749ba15e95f46cd49031739e87"
HEADERS = {"x-apikey": VT_API_KEY}
OUTDIR = "/home/kali/Downloads/sandbox/findings/data"

# Files and their VT analysis IDs
submissions = {
    "u297528.dat_original": "ZGJkOGRiZWNhYTgwNzk1YzEzNTEzN2Q2OTkyMWZkYmE6MTc3OTQyNTQ0Ng==",
    "decrypted_payload.exe": "ZTEwYTliYjA5YWNiNDE1ZTVkYzg2NTRiODU5M2E0NWM6MTc3OTQyNTQ2MQ==",
    "embedded_00.bin": "Y2U1MjdlOWVjMmRkODNjMDU2NTc5NmY1NDIwY2U0ZTQ6MTc3OTQyNTQ3NQ==",
    "embedded_01.bin": "MDA2MTVmMWE0Njg5OWM2NTlhZDk1ODJmNDM0ODlmOWY6MTc3OTQyNTQ3OA==",
}

results = {}

for name, analysis_id in submissions.items():
    print(f"\n[*] Fetching VT results for {name}...")
    url = f"https://www.virustotal.com/api/v3/analyses/{analysis_id}"
    resp = requests.get(url, headers=HEADERS)
    
    if resp.status_code == 200:
        data = resp.json()
        attrs = data.get("data", {}).get("attributes", {})
        stats = attrs.get("stats", {})
        results_list = attrs.get("results", {})
        
        # Count detections
        malicious = stats.get("malicious", 0)
        suspicious = stats.get("suspicious", 0)
        undetected = stats.get("undetected", 0)
        total = malicious + suspicious + undetected + stats.get("harmless", 0) + stats.get("failure", 0)
        
        # Get detected engine names
        detections = []
        for engine, info in results_list.items():
            if info.get("category") == "malicious":
                detections.append({
                    "engine": engine,
                    "result": info.get("result", "N/A")
                })
        
        # Get SHA256 for direct file lookup
        sha256 = data.get("data", {}).get("links", {}).get("item", "").split("/")[-1] if "item" in data.get("data", {}).get("links", {}) else "N/A"
        
        result = {
            "file": name,
            "sha256": sha256,
            "malicious": malicious,
            "suspicious": suspicious,
            "undetected": undetected,
            "total_engines": total,
            "detection_ratio": f"{malicious}/{total}",
            "detection_rate": f"{malicious/total*100:.1f}%" if total > 0 else "N/A",
            "detections": detections[:20],
            "vt_link": f"https://www.virustotal.com/gui/file/{sha256}" if sha256 != "N/A" else "N/A"
        }
        results[name] = result
        
        print(f"  Detection: {malicious}/{total} ({malicious/total*100:.1f}%)")
        print(f"  VT Link: {result['vt_link']}")
        if detections:
            print(f"  Top detections:")
            for d in detections[:10]:
                print(f"    {d['engine']}: {d['result']}")
    else:
        print(f"  Error: HTTP {resp.status_code}")
        results[name] = {"error": f"HTTP {resp.status_code}"}
    
    time.sleep(2)  # Rate limit

# Also try to get the existing VT report by SHA256 hash
print("\n\n[*] Checking existing VT reports by hash...")

known_hashes = {
    "u297528.dat": "e60ab99da105ee27ee09ea64ed8eb46d8edc92ee37f039dbc3e2bb9f587a33ba",
    "decrypted_payload.exe": "d59e83b0be737896dec8b91c7a52f87e16f83e911af52826b98481b5c50f32b2",
}

for name, sha256 in known_hashes.items():
    url = f"https://www.virustotal.com/api/v3/files/{sha256}"
    resp = requests.get(url, headers=HEADERS)
    if resp.status_code == 200:
        data = resp.json()
        attrs = data.get("data", {}).get("attributes", {})
        stats = attrs.get("last_analysis_stats", {})
        names = attrs.get("meaningful_names", [])
        tags = attrs.get("tags", [])
        popularity = attrs.get("popular_threat_classification", {})
        
        print(f"\n  {name}:")
        print(f"    Names: {names[:5]}")
        print(f"    Tags: {tags[:10]}")
        print(f"    Classification: {popularity.get('suggested_threat_label', 'N/A')}")
        print(f"    Stats: {stats}")
    time.sleep(2)

# Save results
with open(os.path.join(OUTDIR, "virustotal_results.json"), 'w') as f:
    json.dump(results, f, indent=2, default=str)

print(f"\n[+] Saved virustotal_results.json")
