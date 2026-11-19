#!/usr/bin/env python3
"""
Script de migration pour associer les anciennes alertes aux domaines surveillés.
Ce script analyse les alertes sans watched_domain_id et tente de les associer
aux domaines surveillés en utilisant la même logique que le script certstream.
"""

import psycopg2
import os
from dotenv import load_dotenv
import re
from typing import Dict, List, Tuple, Optional

# Charger les variables d'environnement
load_dotenv()

# Configuration de la base de données
DB_CONFIG = {
    'host': os.getenv('DB_HOST'),
    'database': os.getenv('DB_NAME'),
    'user': os.getenv('DB_USER'),
    'password': os.getenv('DB_PASS')
}

def load_watched_domains_from_db() -> Dict[str, int]:
    """
    Charge les domaines surveillés depuis la base de données.
    Retourne un dictionnaire {domain: id} avec les variantes www.
    """
    try:
        conn = psycopg2.connect(**DB_CONFIG)
        cursor = conn.cursor()
        
        cursor.execute("SELECT id, domain FROM watched_domains WHERE active = true")
        domains = cursor.fetchall()
        
        domain_mapping = {}
        
        for domain_id, domain in domains:
            # Ajouter le domaine principal
            domain_mapping[domain] = domain_id
            
            # Ajouter la variante avec www si elle n'existe pas déjà
            if domain.startswith('www.'):
                domain_mapping[domain[4:]] = domain_id
            else:
                domain_mapping[f'www.{domain}'] = domain_id
        
        cursor.close()
        conn.close()
        
        print(f"✅ Chargé {len(domains)} domaines surveillés ({len(domain_mapping)} variantes)")
        return domain_mapping
        
    except Exception as e:
        print(f"❌ Erreur lors du chargement des domaines surveillés: {e}")
        return {}

def get_watched_domain_id(detected_domain: str, original_domain: str, domain_mapping: Dict[str, int]) -> Optional[int]:
    """
    Trouve l'ID du domaine surveillé correspondant à une alerte.
    Utilise la même logique que le script certstream.
    """
    # Nettoyer les domaines (enlever protocoles, ports, etc.)
    def clean_domain(domain: str) -> str:
        if not domain:
            return ""
        
        # Enlever les protocoles
        domain = re.sub(r'^https?://', '', domain)
        # Enlever les ports
        domain = re.sub(r':\d+', '', domain)
        # Enlever les chemins
        domain = domain.split('/')[0]
        # Enlever les espaces
        domain = domain.strip()
        
        return domain.lower()
    
    detected_clean = clean_domain(detected_domain) if detected_domain else ""
    original_clean = clean_domain(original_domain) if original_domain else ""
    
    # Chercher d'abord dans le domaine original
    if original_clean and original_clean in domain_mapping:
        return domain_mapping[original_clean]
    
    # Chercher dans le domaine détecté (moins probable mais possible)
    if detected_clean and detected_clean in domain_mapping:
        return domain_mapping[detected_clean]
    
    # Chercher des correspondances partielles dans le domaine original
    if original_clean:
        for watched_domain, domain_id in domain_mapping.items():
            if watched_domain in original_clean or original_clean in watched_domain:
                return domain_id
    
    return None

def analyze_migration_candidates(dry_run: bool = True) -> Tuple[List, int]:
    """
    Analyse les alertes candidates pour la migration.
    """
    try:
        conn = psycopg2.connect(**DB_CONFIG)
        cursor = conn.cursor()
        
        # Charger les domaines surveillés
        domain_mapping = load_watched_domains_from_db()
        if not domain_mapping:
            print("❌ Aucun domaine surveillé trouvé")
            return [], 0
        
        # Récupérer toutes les alertes sans watched_domain_id
        cursor.execute('''
            SELECT id, detected_domain, original_domain, detection_date
            FROM alerts 
            WHERE watched_domain_id IS NULL 
            ORDER BY detection_date DESC
        ''')
        
        old_alerts = cursor.fetchall()
        print(f"\n📊 Analyse de {len(old_alerts)} alertes sans watched_domain_id...")
        
        migration_candidates = []
        matches_found = 0
        
        for alert in old_alerts:
            alert_id, detected_domain, original_domain, detection_date = alert
            
            # Trouver le watched_domain_id correspondant
            watched_domain_id = get_watched_domain_id(detected_domain, original_domain, domain_mapping)
            
            if watched_domain_id:
                matches_found += 1
                migration_candidates.append({
                    'alert_id': alert_id,
                    'detected_domain': detected_domain,
                    'original_domain': original_domain,
                    'watched_domain_id': watched_domain_id,
                    'detection_date': detection_date
                })
                
                if dry_run and len(migration_candidates) <= 10:  # Afficher les 10 premiers en mode dry_run
                    # Trouver le nom du domaine surveillé
                    watched_domain_name = None
                    for domain, domain_id in domain_mapping.items():
                        if domain_id == watched_domain_id:
                            watched_domain_name = domain
                            break
                    
                    print(f"✅ Alerte {alert_id}: {original_domain} → {detected_domain}")
                    print(f"   Correspondance: {watched_domain_name} (ID: {watched_domain_id})")
                    print(f"   Date: {detection_date}")
                    print()
        
        cursor.close()
        conn.close()
        
        print(f"\n📈 Résultats de l'analyse:")
        print(f"   • Total d'alertes analysées: {len(old_alerts)}")
        print(f"   • Correspondances trouvées: {matches_found}")
        print(f"   • Alertes sans correspondance: {len(old_alerts) - matches_found}")
        print(f"   • Taux de correspondance: {(matches_found/len(old_alerts)*100):.1f}%")
        
        return migration_candidates, matches_found
        
    except Exception as e:
        print(f"❌ Erreur lors de l'analyse: {e}")
        return [], 0

def execute_migration(migration_candidates: List) -> int:
    """
    Exécute la migration des alertes.
    """
    if not migration_candidates:
        print("❌ Aucune alerte à migrer")
        return 0
    
    try:
        conn = psycopg2.connect(**DB_CONFIG)
        cursor = conn.cursor()
        
        updated_count = 0
        
        print(f"\n🔄 Migration de {len(migration_candidates)} alertes...")
        
        for candidate in migration_candidates:
            try:
                cursor.execute('''
                    UPDATE alerts 
                    SET watched_domain_id = %s 
                    WHERE id = %s AND watched_domain_id IS NULL
                ''', (candidate['watched_domain_id'], candidate['alert_id']))
                
                if cursor.rowcount > 0:
                    updated_count += 1
                    
            except Exception as e:
                print(f"❌ Erreur lors de la mise à jour de l'alerte {candidate['alert_id']}: {e}")
        
        # Valider les changements
        conn.commit()
        
        cursor.close()
        conn.close()
        
        print(f"✅ Migration terminée: {updated_count} alertes mises à jour")
        return updated_count
        
    except Exception as e:
        print(f"❌ Erreur lors de la migration: {e}")
        return 0

def verify_migration() -> None:
    """
    Vérifie les résultats de la migration.
    """
    try:
        conn = psycopg2.connect(**DB_CONFIG)
        cursor = conn.cursor()
        
        # Compter les alertes avec et sans watched_domain_id
        cursor.execute('SELECT COUNT(*) FROM alerts WHERE watched_domain_id IS NOT NULL')
        with_id = cursor.fetchone()[0]
        
        cursor.execute('SELECT COUNT(*) FROM alerts WHERE watched_domain_id IS NULL')
        without_id = cursor.fetchone()[0]
        
        cursor.execute('SELECT COUNT(*) FROM alerts')
        total = cursor.fetchone()[0]
        
        print(f"\n📊 État après migration:")
        print(f"   • Total d'alertes: {total}")
        print(f"   • Avec watched_domain_id: {with_id}")
        print(f"   • Sans watched_domain_id: {without_id}")
        print(f"   • Couverture: {(with_id/total*100):.1f}%")
        
        # Afficher quelques exemples récents
        cursor.execute('''
            SELECT a.id, a.detected_domain, a.original_domain, w.domain, a.detection_date
            FROM alerts a
            JOIN watched_domains w ON a.watched_domain_id = w.id
            ORDER BY a.detection_date DESC
            LIMIT 5
        ''')
        
        recent_with_id = cursor.fetchall()
        
        print(f"\n🔍 Exemples d'alertes récentes avec watched_domain_id:")
        for alert in recent_with_id:
            print(f"   • ID {alert[0]}: {alert[2]} → {alert[1]} (surveillé: {alert[3]})")
        
        cursor.close()
        conn.close()
        
    except Exception as e:
        print(f"❌ Erreur lors de la vérification: {e}")

def main():
    """
    Fonction principale du script de migration.
    """
    print("🔄 MIGRATION DES ANCIENNES ALERTES CERTSTREAM")
    print("=" * 50)
    
    # Phase 1: Analyse (dry run)
    print("\n📋 Phase 1: Analyse des correspondances possibles...")
    migration_candidates, matches_found = analyze_migration_candidates(dry_run=True)
    
    if matches_found == 0:
        print("❌ Aucune correspondance trouvée. Migration annulée.")
        return
    
    # Demander confirmation
    print(f"\n❓ Voulez-vous procéder à la migration de {matches_found} alertes ? (y/N): ", end="")
    response = input().strip().lower()
    
    if response not in ['y', 'yes', 'oui']:
        print("❌ Migration annulée par l'utilisateur.")
        return
    
    # Phase 2: Migration
    print("\n🔄 Phase 2: Exécution de la migration...")
    updated_count = execute_migration(migration_candidates)
    
    # Phase 3: Vérification
    print("\n✅ Phase 3: Vérification des résultats...")
    verify_migration()
    
    print(f"\n🎉 Migration terminée avec succès!")
    print(f"   {updated_count} alertes ont été associées à leurs domaines surveillés.")

if __name__ == "__main__":
    main()