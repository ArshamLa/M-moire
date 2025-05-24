# code généré par github copilot
import os
import json
import csv

def load_report(path):
    with open(path, 'r', encoding='utf-8') as f:
        return json.load(f)

def count_files_written(data):
    total = 0
    for entry in data:
        attrs = entry.get('attributes', {})
        lst = attrs.get('files_written', [])
        if isinstance(lst, list):
            total += len(lst)
    return total

def count_files_deleted(data):
    total = 0
    for entry in data:
        attrs = entry.get('attributes', {})
        lst = attrs.get('files_deleted', [])
        if isinstance(lst, list):
            total += len(lst)
    return total

def count_files_dropped(data):
    total = 0
    for entry in data:
        attrs = entry.get('attributes', {})
        lst = attrs.get('files_dropped', [])
        if isinstance(lst, list):
            total += len(lst)
    return total

def detect_ransom_note(data):
    note_names = ('readme.txt', 'howtodecrypt.html')
    for entry in data:
        attrs = entry.get('attributes', {})
        for key in ('files_written','files_dropped','files_opened','files_copied'):
            lst = attrs.get(key, [])
            if isinstance(lst, list):
                for item in lst:
                    name = item if isinstance(item, str) else item.get('name') or item.get('path') or ''
                    if any(note in name.lower() for note in note_names):
                        return True
    return False

def count_registry_mods(data):
    total = 0
    for entry in data:
        attrs = entry.get('attributes', {})
        regs = attrs.get('registry_keys_set')
        if isinstance(regs, list):
            total += len(regs)
    return total

def process_report(path, sha256, target):
    report = load_report(path)
    data = report.get('data', [])

    files_written       = count_files_written(data)
    files_deleted       = count_files_deleted(data)
    files_dropped       = count_files_dropped(data)
    ransom_note_flag    = detect_ransom_note(data)
    registry_mods       = count_registry_mods(data)


    print(f"SHA256                 : {sha256}")
    print(f"Target                 : {target}")
    print(f"Fichiers écrits        : {files_written}")
    print(f"Fichiers supprimés     : {files_deleted}")
    print(f"Fichiers dropped       : {files_dropped}")
    print(f"Ransom-note présente    : {ransom_note_flag}")
    print(f"Modifs registre        : {registry_mods}")
    print()

    return {
        'sha256': sha256,
        'files_written': files_written,
        'files_deleted': files_deleted,
        'files_dropped': files_dropped,
        'ransom_note': int(ransom_note_flag),
        'registry_mods': registry_mods,
        'target': target
    }

if __name__ == "__main__":
    folders = {
        '/home/arsham/memoire/report_benin': 0,
        '/home/arsham/memoire/report_ransomware': 1,
    }

    csv_path = 'dynamique_features_dataset.csv'
    fieldnames = [
        'sha256',
        'files_written',
        'files_deleted',
        'files_dropped',
        'ransom_note',
        'registry_mods',
        'target'
    ]
    with open(csv_path, 'w', newline='', encoding='utf-8') as csvfile:
        writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
        writer.writeheader()

        files = []
        for folder, target in folders.items():
            for fname in os.listdir(folder):
                if fname.lower().endswith('.json'):
                    sha256 = os.path.splitext(fname)[0]
                    files.append((os.path.join(folder, fname), sha256, target))

        total = len(files)
        for i, (path, sha256, target) in enumerate(files, start=1):
            print(f"[{i}/{total}] Traitement du rapport {sha256}.json")
            row = process_report(path, sha256, target)
            writer.writerow(row)

    print(f"Traitement terminé. CSV généré: {csv_path}")
