import csv
import psycopg2
from pathlib import Path
import re
from datetime import datetime
import logging

# Configuration du logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('import_csv.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

# Configuration DB PostgreSQL
DB_CONFIG = {
    "dbname": "typoscan",
    "user": "typo_user",
    "password": "typo_pass",
    "host": "localhost",
    "port": 5432
}

# Chemin du dossier contenant les fichiers CSV
CSV_FOLDER = Path("/home/typo_user/Typosquatting/dnstwist/Data/all/")  # <-- à adapter

def get_csv_files(folder_path):
    """
    Récupère tous les fichiers CSV correspondant au pattern rapport_aaaammjj_hhmm.csv
    et les trie par date (du plus ancien au plus récent)
    """
    pattern = re.compile(r'^rapport_(\d{8})_(\d{4})\.csv$')
    csv_files = []
    
    for file_path in folder_path.glob("rapport_*.csv"):
        match = pattern.match(file_path.name)
        if match:
            date_str = match.group(1)  # aaaammjj
            time_str = match.group(2)  # hhmm
            try:
                # Convertir en datetime pour le tri
                dt = datetime.strptime(f"{date_str}_{time_str}", "%Y%m%d_%H%M")
                csv_files.append((dt, file_path))
            except ValueError:
                logger.warning(f"Format de date invalide pour le fichier : {file_path.name}")
    
    # Trier par date
    csv_files.sort(key=lambda x: x[0])
    return [file_path for _, file_path in csv_files]

def create_processed_files_table(cursor):
    """
    Crée une table pour suivre les fichiers déjà traités
    """
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS processed_files (
            id SERIAL PRIMARY KEY,
            filename VARCHAR(255) UNIQUE NOT NULL,
            processed_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            records_count INTEGER DEFAULT 0
        )
    ''')

def is_file_already_processed(cursor, filename):
    """
    Vérifie si un fichier a déjà été traité
    """
    cursor.execute("SELECT id FROM processed_files WHERE filename = %s", (filename,))
    return cursor.fetchone() is not None

def mark_file_as_processed(cursor, filename, records_count):
    """
    Marque un fichier comme traité
    """
    cursor.execute('''
        INSERT INTO processed_files (filename, records_count) 
        VALUES (%s, %s)
        ON CONFLICT (filename) DO UPDATE SET
            processed_at = CURRENT_TIMESTAMP,
            records_count = EXCLUDED.records_count
    ''', (filename, records_count))

def get_or_create_watched_domain(cursor, domain):
    """
    Récupère ou crée un domaine surveillé
    """
    cursor.execute("SELECT id FROM watched_domains WHERE domain = %s", (domain,))
    result = cursor.fetchone()
    if result:
        return result[0]
    cursor.execute(
        "INSERT INTO watched_domains (domain) VALUES (%s) RETURNING id",
        (domain,)
    )
    return cursor.fetchone()[0]

def alert_exists(cursor, watched_domain_id, detected_domain):
    """
    Vérifie si une alerte existe déjà pour éviter les doublons
    """
    cursor.execute('''
        SELECT id FROM alerts 
        WHERE watched_domain_id = %s AND detected_domain = %s
    ''', (watched_domain_id, detected_domain))
    return cursor.fetchone() is not None

def insert_alert(cursor, data):
    """
    Insère une nouvelle alerte si elle n'existe pas déjà
    """
    if not alert_exists(cursor, data["watched_domain_id"], data["detected_domain"]):
        cursor.execute('''
            INSERT INTO alerts (
                source, watched_domain_id, detected_domain,
                dns_a, dns_mx, dns_ns,
                whois_created, whois_registrar
            ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s)
        ''', (
            data["source"],
            data["watched_domain_id"],
            data["detected_domain"],
            data["dns_a"],
            data["dns_mx"],
            data["dns_ns"],
            data["whois_created"],
            data["whois_registrar"]
        ))
        return True
    return False

def process_csv_file(cursor, csv_path):
    """
    Traite un fichier CSV spécifique
    """
    logger.info(f"Traitement du fichier : {csv_path.name}")
    
    if not csv_path.exists():
        logger.error(f"Fichier introuvable : {csv_path}")
        return 0
    
    count_new = 0
    count_duplicates = 0
    
    try:
        with open(csv_path, "r", encoding="utf-8", errors="replace") as f:
            reader = csv.DictReader(f)
            
            for row_num, row in enumerate(reader, 1):
                try:
                    original = row.get("Domaine d'origine", "").strip()
                    detected = row.get("Domaine détecté", "").strip()
                    
                    if not original or not detected:
                        logger.debug(f"Ligne {row_num} ignorée : domaine manquant")
                        continue

                    watched_domain_id = get_or_create_watched_domain(cursor, original)

                    alert_data = {
                        "source": "dnstwist",
                        "watched_domain_id": watched_domain_id,
                        "detected_domain": detected,
                        "dns_a": row.get("IP", "").strip(),
                        "dns_mx": row.get("MX", "").strip(),
                        "dns_ns": row.get("NS", "").strip(),
                        "whois_created": row.get("Date de création", "").strip(),
                        "whois_registrar": row.get("Registrar", "").strip(),
                    }

                    if insert_alert(cursor, alert_data):
                        count_new += 1
                    else:
                        count_duplicates += 1
                        
                except Exception as e:
                    logger.error(f"Erreur ligne {row_num} dans {csv_path.name}: {e}")
                    continue
    
    except Exception as e:
        logger.error(f"Erreur lors de la lecture du fichier {csv_path.name}: {e}")
        return 0
    
    logger.info(f"Fichier {csv_path.name}: {count_new} nouvelles alertes, {count_duplicates} doublons ignorés")
    return count_new

def import_all_csv_reports(force_reprocess=False):
    """
    Importe tous les rapports CSV du dossier
    """
    if not CSV_FOLDER.exists():
        logger.error(f"Dossier introuvable : {CSV_FOLDER}")
        return

    csv_files = get_csv_files(CSV_FOLDER)
    if not csv_files:
        logger.warning(f"Aucun fichier CSV trouvé dans : {CSV_FOLDER}")
        return

    logger.info(f"Trouvé {len(csv_files)} fichiers CSV à traiter")

    total_new_alerts = 0
    total_processed_files = 0
    total_skipped_files = 0

    try:
        with psycopg2.connect(**DB_CONFIG) as conn:
            with conn.cursor() as cursor:
                # Créer la table de suivi si elle n'existe pas
                create_processed_files_table(cursor)
                
                for csv_file in csv_files:
                    try:
                        # Vérifier si le fichier a déjà été traité
                        if not force_reprocess and is_file_already_processed(cursor, csv_file.name):
                            logger.info(f"Fichier déjà traité, ignoré : {csv_file.name}")
                            total_skipped_files += 1
                            continue
                        
                        # Traiter le fichier
                        new_alerts = process_csv_file(cursor, csv_file)
                        
                        # Marquer comme traité
                        mark_file_as_processed(cursor, csv_file.name, new_alerts)
                        
                        total_new_alerts += new_alerts
                        total_processed_files += 1
                        
                        # Commit après chaque fichier pour éviter de perdre le travail
                        conn.commit()
                        
                    except Exception as e:
                        logger.error(f"Erreur lors du traitement de {csv_file.name}: {e}")
                        conn.rollback()
                        continue

                logger.info(f"""
=== RÉSUMÉ ===
Fichiers traités : {total_processed_files}
Fichiers ignorés (déjà traités) : {total_skipped_files}
Total nouvelles alertes ajoutées : {total_new_alerts}
""")

    except Exception as e:
        logger.error(f"Erreur de connexion à la base de données : {e}")

def main():
    """
    Fonction principale avec options
    """
    import argparse
    
    parser = argparse.ArgumentParser(description='Import des rapports CSV dans PostgreSQL')
    parser.add_argument('--force', action='store_true', 
                       help='Force le retraitement des fichiers déjà traités')
    parser.add_argument('--file', type=str, 
                       help='Traiter un fichier spécifique au lieu de tout le dossier')
    
    args = parser.parse_args()
    
    if args.file:
        # Traiter un fichier spécifique
        csv_path = Path(args.file)
        if not csv_path.is_absolute():
            csv_path = CSV_FOLDER / csv_path
            
        with psycopg2.connect(**DB_CONFIG) as conn:
            with conn.cursor() as cursor:
                create_processed_files_table(cursor)
                new_alerts = process_csv_file(cursor, csv_path)
                mark_file_as_processed(cursor, csv_path.name, new_alerts)
                conn.commit()
    else:
        # Traiter tous les fichiers
        import_all_csv_reports(force_reprocess=args.force)

if __name__ == "__main__":
    main()