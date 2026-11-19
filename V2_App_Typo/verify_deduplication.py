#!/usr/bin/env python3
"""
Script de vérification de la déduplication
"""

import os
import sys
import psycopg2
import logging
from dotenv import load_dotenv

# Configuration de logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# Charger les variables d'environnement depuis .env
load_dotenv()

def get_db_connection():
    """Connexion à la base de données PostgreSQL"""
    try:
        conn = psycopg2.connect(
            host=os.getenv('DB_HOST', 'localhost'),
            database=os.getenv('DB_NAME', 'typoscan'),
            user=os.getenv('DB_USER', 'typo_user'),
            password=os.getenv('DB_PASS', 'typo_password'),
            port=os.getenv('DB_PORT', '5432')
        )
        return conn
    except Exception as e:
        logging.error(f"Erreur de connexion à la base de données: {e}")
        sys.exit(1)

def check_duplicates(conn):
    """Vérifie s'il reste des doublons"""
    cursor = conn.cursor()
    
    # Compter les doublons restants
    cursor.execute("""
        SELECT 
            detected_domain,
            watched_domain_id,
            COUNT(*) as count
        FROM alerts 
        GROUP BY detected_domain, watched_domain_id
        HAVING COUNT(*) > 1
        ORDER BY count DESC
        LIMIT 10;
    """)
    
    duplicates = cursor.fetchall()
    
    if duplicates:
        print("❌ Doublons restants détectés:")
        for domain, watched_id, count in duplicates:
            print(f"   - {domain} (watched_id: {watched_id}): {count} fois")
        return False
    else:
        print("✅ Aucun doublon détecté")
        return True

def check_constraints(conn):
    """Vérifie que les contraintes sont en place"""
    cursor = conn.cursor()
    
    # Vérifier l'index unique
    cursor.execute("""
        SELECT indexname 
        FROM pg_indexes 
        WHERE tablename = 'alerts' 
        AND indexname = 'idx_alerts_unique_domain';
    """)
    
    index_exists = cursor.fetchone() is not None
    
    # Vérifier la contrainte CHECK
    cursor.execute("""
        SELECT conname 
        FROM pg_constraint 
        WHERE conname = 'chk_detected_domain_not_empty';
    """)
    
    check_exists = cursor.fetchone() is not None
    
    print(f"🔒 Index unique: {'✅ Présent' if index_exists else '❌ Absent'}")
    print(f"🔒 Contrainte CHECK: {'✅ Présente' if check_exists else '❌ Absente'}")
    
    return index_exists and check_exists

def get_stats(conn):
    """Affiche les statistiques générales"""
    cursor = conn.cursor()
    
    # Statistiques générales
    cursor.execute("SELECT COUNT(*) FROM alerts;")
    total_alerts = cursor.fetchone()[0]
    
    cursor.execute("SELECT COUNT(DISTINCT detected_domain) FROM alerts;")
    unique_domains = cursor.fetchone()[0]
    
    cursor.execute("""
        SELECT source, COUNT(*) 
        FROM alerts 
        GROUP BY source 
        ORDER BY COUNT(*) DESC;
    """)
    sources = cursor.fetchall()
    
    print(f"\n📊 Statistiques:")
    print(f"   - Total alertes: {total_alerts}")
    print(f"   - Domaines uniques: {unique_domains}")
    print(f"   - Sources:")
    for source, count in sources:
        print(f"     * {source or 'None'}: {count}")

def main():
    """Fonction principale"""
    print("🔍 Vérification de la déduplication")
    print("=" * 40)
    
    conn = get_db_connection()
    
    try:
        # Vérifier les doublons
        print("\n1. Vérification des doublons restants...")
        no_duplicates = check_duplicates(conn)
        
        # Vérifier les contraintes
        print("\n2. Vérification des contraintes...")
        constraints_ok = check_constraints(conn)
        
        # Statistiques
        print("\n3. Statistiques générales...")
        get_stats(conn)
        
        # Résumé
        print(f"\n{'='*40}")
        if no_duplicates and constraints_ok:
            print("✅ Déduplication réussie!")
            print("   - Aucun doublon détecté")
            print("   - Contraintes en place")
            print("   - Système protégé contre les futurs doublons")
        else:
            print("⚠️  Problèmes détectés:")
            if not no_duplicates:
                print("   - Des doublons sont encore présents")
            if not constraints_ok:
                print("   - Les contraintes ne sont pas en place")
        
    except Exception as e:
        logging.error(f"Erreur durant la vérification: {e}")
    finally:
        conn.close()

if __name__ == "__main__":
    main()