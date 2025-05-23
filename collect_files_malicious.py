
import os
import io
import zipfile
import requests
import hashlib

API_URL     = "https://mb-api.abuse.ch/api/v1/"
API_KEY     = "7cfb7a65f0266a89f6989919adf03fba1777ace81c686d3b"
BASE_DIR    = os.path.dirname(os.path.abspath(__file__))
PARENT_DIR  = os.path.dirname(BASE_DIR)
DOWNLOAD_DIR= os.path.join(PARENT_DIR, 'malicious_files')

# essaye d’importer pyzipper pour le support AES
try:
    import pyzipper
except ImportError:
    pyzipper = None


def download_and_verify(sha256,n, output_dir=DOWNLOAD_DIR):
    """
    Télécharge le ZIP protégé, extrait le fichier à l'intérieur en utilisant
    son nom interne (avec extension), vérifie le SHA256 et enregistre le résultat.
    """
    os.makedirs(output_dir, exist_ok=True)

    # 1) Télécharger le ZIP
    resp = requests.post(
        API_URL,
        headers={'Auth-Key': API_KEY},
        data={'query': 'get_file', 'sha256_hash': sha256},
        timeout=60
    )
    resp.raise_for_status()
    content = resp.content

    # 2) Extraction en mémoire
    try:
        if pyzipper:
            with pyzipper.AESZipFile(io.BytesIO(content)) as zf:
                zf.pwd = b'infected'
                members = zf.namelist()
                data = zf.read(members[0])
        else:
            zf = zipfile.ZipFile(io.BytesIO(content))
            members = zf.namelist()
            data = zf.read(members[0], pwd=b'infected')
    except Exception as e:
        print(f"[ERREUR] {sha256} → impossible de dézipper : {e}")
        return

    if not members:
        print(f"[ERREUR] {sha256} → archive vide.")
        return

    # 3) Détermination du nom interne et chemin final
    internal_name = members[0]
    safe_name = internal_name.replace('/', '_').replace('\\', '_')
    filename = f"{safe_name}"
    path = os.path.join(output_dir, filename)

    # Skip si déjà présent
    if os.path.exists(path):
        print(f"[SKIP] {filename} déjà présent.")
        return

    # 4) Vérification du SHA256
    computed = hashlib.sha256(data).hexdigest()
    if computed.lower() != sha256.lower():
        print(f"[KO]    {filename} — hash mismatch ! attendu {sha256}, obtenu {computed}")
        return

    # 5) Enregistrement du fichier
    with open(path, 'wb') as f:
        f.write(data)
    print(f"[OK]    {filename} — téléchargé et vérifié - count : {n}")
    


def list_and_download_ransomware_exes(limit=1000):
    """
    1) Récupère jusqu'à limit métadonnées taggées 'ransomware'
    2) Filtre celles taggées 'exe'
    3) Télécharge et vérifie chaque sample
    """
    headers = {'Auth-Key': API_KEY}
    payload = {'query': 'get_taginfo', 'tag': 'ransomware', 'limit': str(limit)}

    resp = requests.post(API_URL, headers=headers, data=payload, timeout=100)
    resp.raise_for_status()
    result = resp.json()
    if result.get('query_status') != 'ok':
        print(f"[ERREUR] get_taginfo → {result.get('query_status')}")
        return

    samples = result.get('data', [])
    exe_samples = [
        s for s in samples
        if 'exe' in [t.lower() for t in (s.get('tags') or [])]
    ]
    n=1
    print(f"=== {len(exe_samples)} ransomwares .exe à télécharger ===")
    for s in exe_samples:
        download_and_verify(s['sha256_hash'],n)
        n+=1

if __name__ == "__main__":
    list_and_download_ransomware_exes()
