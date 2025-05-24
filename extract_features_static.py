# code généré par github copilot
import os
import re
import csv
import hashlib
import numpy as np
from scipy.stats import entropy
import pefile
import peutils  # module du package pefile


def extract_entropy_global(file_path: str) -> float:
    try:
        with open(file_path, "rb") as f:
            data = f.read()
    except Exception:
        return 0.0
    counts = np.bincount(np.frombuffer(data, dtype=np.uint8), minlength=256)
    probs = counts / counts.sum() if counts.sum() > 0 else counts
    return entropy(probs, base=2)


def extract_entropy_text_section(file_path: str) -> float:
    try:
        pe = pefile.PE(file_path)
    except pefile.PEFormatError:
        return 0.0
    for section in pe.sections:
        if section.Name.rstrip(b'\x00') == b'.text':
            try:
                data = section.get_data()
            except Exception:
                return 0.0
            counts = np.bincount(np.frombuffer(data, dtype=np.uint8), minlength=256)
            probs = counts / counts.sum() if counts.sum() > 0 else counts
            return entropy(probs, base=2)
    return 0.0


def extract_entropy_data_section(file_path: str) -> float:
    try:
        pe = pefile.PE(file_path)
    except pefile.PEFormatError:
        return 0.0
    for section in pe.sections:
        if section.Name.rstrip(b'\x00') == b'.data':
            try:
                data = section.get_data()
            except Exception:
                return 0.0
            counts = np.bincount(np.frombuffer(data, dtype=np.uint8), minlength=256)
            probs = counts / counts.sum() if counts.sum() > 0 else counts
            return entropy(probs, base=2)
    return 0.0


def extract_invalid_checksum(file_path: str) -> int:
    try:
        pe = pefile.PE(file_path)
        declared = pe.OPTIONAL_HEADER.CheckSum
        calculated = pe.generate_checksum()
    except Exception:
        return 1
    return int(declared != calculated)


def extract_num_sections(file_path: str) -> int:
    try:
        pe = pefile.PE(file_path)
        return int(pe.FILE_HEADER.NumberOfSections)
    except Exception:
        return -1


# cette fonction ci-dessous permet de calculer la taille moyenne des sections
def extract_mean_raw_section_size(file_path: str) -> float:
    try:
        pe = pefile.PE(file_path)
        sizes = [section.SizeOfRawData for section in pe.sections]
        return sum(sizes) / len(sizes) if sizes else 0.0
    except Exception:
        return 0.0


def write_results_to_csv(files_with_target, output_path='résultats.csv'):
    i_count = 1
    """
    Génère un fichier CSV avec les métriques extraites pour chaque fichier PE.
    `files_with_target` est une liste de tuples (file_path, target).
    Les colonnes sont séparées par des virgules, et les décimales utilisent un point.
    """
    headers = [
        'nom_fichier', 'entropie_globale', 'entropie_section_text',
        'entropie_section_data','checksum_invalide', 'nombre_sections', 'taille_moyenne_section',
        'target'
    ]
    with open(output_path, 'w', newline='', encoding='utf-8') as csvfile:
        writer = csv.writer(csvfile, delimiter=',')
        writer.writerow(headers)
        for file_path, target in files_with_target:
            # Vérification du nom SHA256 vs contenu
            base_name = os.path.splitext(os.path.basename(file_path))[0]
            hasher = hashlib.sha256()
            with open(file_path, 'rb') as f:
                for chunk in iter(lambda: f.read(8192), b''):
                    hasher.update(chunk)
            real_sha = hasher.hexdigest()
            sha_match = (real_sha.lower() == base_name.lower())
            print(f"{file_path} SHA256 match: {sha_match} - count {i_count}")
            i_count +=1
            if not sha_match:
                continue  # skip si le nom ne correspond pas

            # Extraction des métriques
            ent_global = extract_entropy_global(file_path)
            ent_text = extract_entropy_text_section(file_path)
            ent_data = extract_entropy_data_section(file_path)
            invalid_checksum = extract_invalid_checksum(file_path)
            num_sections = extract_num_sections(file_path)
            mean_raw_size = extract_mean_raw_section_size(file_path)


            writer.writerow([
                os.path.basename(file_path), f"{ent_global:.6f}",
                f"{ent_text:.6f}", f"{ent_data:.6f}",
                str(invalid_checksum), str(num_sections),
                f"{mean_raw_size:.6f}", str(target)

            ])


if __name__ == "__main__":
    mapping = {
        '/home/arsham/memoire/analyse_statique_benin': 0,
        '/home/arsham/memoire/analyse_statique_ransomware': 1
    }
    files_with_target = []
    for folder, label in mapping.items():
        for dirpath, _, filenames in os.walk(folder):
            for fname in filenames:
                fullpath = os.path.join(dirpath, fname)
                files_with_target.append((fullpath, label))
    write_results_to_csv(files_with_target)
    print("CSV généré : 'résultats.csv'")
