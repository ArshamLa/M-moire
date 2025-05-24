# code généré par github copilot
import os
import shutil
import hashlib
from pathlib import Path

# 1) CONFIGURATION : liste des répertoires sources
SRC_DIRS = [
    Path(r"C:\Windows\System32"),
    Path(r"C:\Windows\SysWOW64"),
    Path(r"C:\Program Files"),
    Path(r"C:\Program Files (x86)")
]

# Dossier de sortie
DEST_DIR = Path(r"C:\Users\arsha\Documents\mémoire\articles mémoire\benin")

# Nombre cible d'exécutables
TARGET = 810
EXT    = ".exe"

# Crée le dossier de destination s’il n’existe pas
DEST_DIR.mkdir(parents=True, exist_ok=True)

# 2) Fonction de calcul du SHA256
def sha256sum(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(8192), b""):
            h.update(chunk)
    return h.hexdigest()

# 3) Parcours, dé-duplication et copie
collected_hashes = set()
count = 0

for src in SRC_DIRS:
    if count >= TARGET:
        break
    if not src.exists():
        continue
# root contient le chemin du dossier, _ contient les sous-dossiers et files contient les fichiers
    for root, _, files in os.walk(src):
        if count >= TARGET:
            break

        for filename in files:
            if count >= TARGET:
                break
            if not filename.lower().endswith(EXT):
                continue
# src_path contient le chemin complet du fichier, root contient le chemin du dossier 
            src_path = Path(root) / filename

            # Calcul du SHA256
            try:
                #
                h = sha256sum(src_path)
            except Exception:
                continue  # accès refusé ou problème de lecture

            # On n'ajoute que si ce hash n'a pas déjà été copié
            if h in collected_hashes:
                continue

            # Copie sous le nom <SHA256>.exe
            dest_path = DEST_DIR / f"{h}{EXT}"
            try:
                shutil.copy2(src_path, dest_path)
                collected_hashes.add(h)
                count += 1
                # Affiche un point d'avancement tous les 50 fichiers
                if count % 50 == 0 or count == TARGET:
                    print(f"  • {count} exécutables distincts copiés")
            except Exception:
                # skip en cas d'erreur de copie
                continue

print(f"\n Opération terminée : {count} exécutables distincts copiés dans :\n   {DEST_DIR}")
