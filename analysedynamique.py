
# #!/usr/bin/env python3
import time
import requests
import hashlib
import json
import subprocess
from pathlib import Path

# ── CONFIG ────────────────────────────────────────────────────────────────
API_KEYS = [
    # Tes 12 clés API
    "b93823a2ff762c9e57d8a8c733bf8b64ccdf2ba0f1e8829c4955d83c923839a5",
    "c8512900d2637160b52cffb14052791fa7f4fe77e424724b83fac03f89d483a0",
    "55aae143e5adf886ce249d7bd90913c9c4b17db7bd1b81d1238f1f5ac46fe6fa",
    "31511f3988e30d4b0746f5af69d902bf93c5cd402ce32c9df3821811feaf8556",
    "f3d1a73412255a97128b61284275115fdc02d237e3fd595caa641e87d989c851",
    "b013f4b7ed7a5651c710296c81060f72f4bdff54d11a7c05116a8eb567855631",
    "be5be4be664e74d8e33ff47698e99e9335a4c8f73bf6ffba79d9284bb12b598c",
    "148fd5a714200fc085c71bd3d1d463bd2366fba6c5f7263fb7581116c9c1c219",
    "611c4ceb5f0ce974bf668766a0b58fe6545c60bfb19f18a806d5347f134d2193",
    "ca6dcc5a2b215ab9e21a189225d9b398c32611f549eb83c866f94dedfd826820",
    "8e06eba8d90147968828003c0ba1bee3f75d95c65367860861a2ed3ce7172880",
    "1c204c93d57b6c341e21d882127c6ce11046818eb5d8ab359e05d79c02f1ac6a"
]
BASE = Path("/home/arsham/memoire")
CONFIGS = [
    {
        "src": BASE / "analyse_dynamique_benin",
        "done": BASE / "analyse_dynamique_benin_done",
        "report": BASE / "report_benin",
        "fail": BASE / "analyse_dynamique_benin_fail"
    },
    {
        "src": BASE / "analyse_dynamique_ransomware",
        "done": BASE / "analyse_dynamique_ransomware_done",
        "report": BASE / "report_ransomware",
        "fail": BASE / "analyse_dynamique_ransomware_fail"
    }
]

# Nombre max de requêtes avant changement VPN
REQUEST_LIMIT = 408
# Durée d'attente après soumission (en secondes)
FIXED_WAIT = 360  # 6 minutes
# Emplacements VPN (pays, ville)
LOCATIONS = [
    ("Germany",    "Frankfurt"),
    ("Germany",    "Hamburg"),
    ("Luxembourg", "Luxembourg"),
    ("Netherlands","Amsterdam"),
    ("Switzerland","Zurich"),
    ("Italy",      "Milan"),
    ("Italy",      "Palermo"),
    ("Italy",      "Rome"),
    ("Spain",      "Barcelona"),
    ("Spain",      "Madrid")
]

# Global state
req_count = 0
vpn_index = 0

class RequestLimitReached(Exception):
    pass

# Switch VPN to given location
def switch_vpn(country: str, city: str):
    print(f"[VPN   ] Switching VPN to {country}, {city}")
    subprocess.run(["nordvpn", "disconnect"], check=False)
    subprocess.run(["nordvpn", "connect", country, city], check=True)
    time.sleep(5)
    print(f"[VPN   ] Connected to {country}, {city}")

# Increment request count and enforce limit
def increment_request():
    global req_count
    req_count += 1
    print(f"[REQ COUNT] {req_count}")
    if req_count >= REQUEST_LIMIT:
        raise RequestLimitReached()

# Compute file SHA256
def compute_sha256(filepath: Path) -> str:
    h = hashlib.sha256()
    with filepath.open("rb") as f:
        for chunk in iter(lambda: f.read(8192), b""):
            h.update(chunk)
    return h.hexdigest()

# Submit file to VirusTotal
def submit_file(filepath: Path, api_key: str):
    increment_request()
    headers = {"x-apikey": api_key}
    url = "https://www.virustotal.com/api/v3/files"
    with filepath.open("rb") as f:
        files = {"file": (filepath.name, f)}
        r = requests.post(url, headers=headers, files=files)
    print(f"[SUBMIT] Key={api_key[:6]}… | File={filepath.name} → {r.status_code} {r.reason}")
    try:
        r.raise_for_status()
    except requests.exceptions.HTTPError as e:
        if r.status_code == 413:
            return "413"
        else:
            raise
    return r.json()["data"]["id"]

# Fetch dynamic analysis report
def fetch_report_json(sha256: str, api_key: str) -> dict:
    increment_request()
    headers = {"x-apikey": api_key}
    url = f"https://www.virustotal.com/api/v3/files/{sha256}/behaviours"
    r = requests.get(url, headers=headers)
    print(f"[FETCH ] Key={api_key[:6]}… | SHA256={sha256} → {r.status_code} {r.reason}")
    r.raise_for_status()
    return r.json()

# Save report locally
def save_report(report: dict, outdir: Path, basename: str):
    outdir.mkdir(parents=True, exist_ok=True)
    path = outdir / f"{basename}.json"
    with path.open("w", encoding="utf-8") as f:
        json.dump(report, f, ensure_ascii=False, indent=2)
    print(f"[SAVE  ] Report saved to {path}")

# Main processing loop
def main():
    global vpn_index, req_count
    # Collect all files
    files_info = []
    for cfg in CONFIGS:
        src = cfg["src"]
        if not src.exists():
            continue
        for file in src.iterdir():
            if file.is_file():
                files_info.append({
                    "filepath": file,
                    "done": cfg["done"],
                    "report": cfg["report"],
                    "fail": cfg["fail"]
                })

    total_files = len(files_info)
    idx = 0
    batch_size = len(API_KEYS)

    while idx < total_files:
        try:
            country, city = LOCATIONS[vpn_index]
            print(f"\n[INFO  ] Processing files {idx+1}-{min(idx+batch_size, total_files)} of {total_files} on VPN {country},{city}")
            # Prepare batch
            batch = files_info[idx: idx + batch_size]
            pending = []
            # Submit batch
            for api_key, info in zip(API_KEYS, batch):
                fp = info["filepath"]
                sha256 = compute_sha256(fp)
                res = submit_file(fp, api_key)
                if res == "413":
                    # Move to fail directory
                    info["fail"].mkdir(parents=True, exist_ok=True)
                    dest = info["fail"] / fp.name
                    fp.rename(dest)
                    print(f"[FAIL ] File too large, moved {fp.name} to {dest}")
                    continue
                analysis_id = res
                pending.append({
                    "api_key": api_key,
                    "sha256": sha256,
                    "filepath": fp,
                    "done": info["done"],
                    "report": info["report"]
                })

            # Wait for sandbox completion
            print(f"[INFO  ] Waiting {FIXED_WAIT}s for analysis...\n")
            time.sleep(FIXED_WAIT)

            # Fetch reports and move files
            for item in pending:
                report = fetch_report_json(item["sha256"], item["api_key"])
                save_report(report, item["report"], item["filepath"].stem)
                item["done"].mkdir(parents=True, exist_ok=True)
                dest = item["done"] / item["filepath"].name
                item["filepath"].rename(dest)
                print(f"[MOVE  ] Moved {item['filepath'].name} to {dest}\n")

            # Advance index
            idx += batch_size

        except RequestLimitReached:
            # Rotate VPN and reset counter
            vpn_index = (vpn_index + 1) % len(LOCATIONS)
            req_count = 0
            switch_vpn(*LOCATIONS[vpn_index])
            print(f"[INFO  ] Resuming from file index {idx+1}...\n")
            continue

    print("\n[INFO  ] All files processed.")

if __name__ == "__main__":
    switch_vpn(*LOCATIONS[vpn_index])
    main()
