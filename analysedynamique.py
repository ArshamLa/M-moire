# code généré par github copilot
import time
import requests
import hashlib
import json
import subprocess
from pathlib import Path

# ── CONFIG ────────────────────────────────────────────────────────────────
API_KEYS = [
    # Tes 12 clés API
    "x",
    "y",
    "z",
    "u",
    "f",
    "d",
    "b",
    "c",
    "s",
    "k",
    "w",
    "r"
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
