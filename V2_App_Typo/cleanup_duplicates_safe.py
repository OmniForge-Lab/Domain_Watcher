#!/usr/bin/env python3
"""
Script sécurisé pour nettoyer les doublons avec sauvegarde
"""

import os
import sys
import psycopg2
from datetime import datetime
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
            host=os.getenv('DB_HOST'),
            database=os.getenv('DB_NAME'),
            user=os.getenv('DB_USER'),
            password=os.getenv('DB_PASS'),
            port=os.getenv('DB_PORT')
        )
        return conn
    except Exception as e:
        logging.error(f"Erreur de connexion à la base de données: {e}")
        sys.exit(1)

def backup_duplicates(conn):
    """Sauvegarde les doublons avant suppression"""
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    backup_table = f"alerts_duplicates_backup_{timestamp}"
    
    cursor = conn.cursor()
    
    # Créer une table de sauvegarde avec les doublons
    backup_query = f"""
    CREATE TABLE {backup_table} AS
    SELECT a.* FROM alerts a
    WHERE a.id NOT IN (
        SELECT MIN(id) 
        FROM alerts 
        GROUP BY watched_domain_id, detected_domain
    );
    """
    
    cursor.execute(backup_query)
    
    # Compter les enregistrements sauvegardés
    cursor.execute(f"SELECT COUNT(*) FROM {backup_table}")
    backup_count = cursor.fetchone()[0]
    
    conn.commit()
    logging.info(f"✅ {backup_count} doublons sauvegardés dans la table {backup_table}")
    return backup_table, backup_count

def remove_duplicates(conn):
    """Supprime les doublons en gardant le plus ancien"""
    cursor = conn.cursor()
    
    # Supprimer les doublons (garder le MIN(id) = le plus ancien)
    delete_query = """
    DELETE FROM alerts 
    WHERE id NOT IN (
        SELECT MIN(id) 
        FROM alerts 
        GROUP BY watched_domain_id, detected_domain
    );
    """
    
    cursor.execute(delete_query)
    deleted_count = cursor.rowcount
    conn.commit()
    
    logging.info(f"✅ {deleted_count} doublons supprimés")
    return deleted_count

def add_unique_constraint(conn):
    """Ajoute la contrainte d'unicité"""
    cursor = conn.cursor()
    
    try:
        # Ajouter l'index unique
        cursor.execute("""
            CREATE UNIQUE INDEX IF NOT EXISTS idx_alerts_unique_domain 
            ON alerts (watched_domain_id, detected_domain);
        """)
        
        # Ajouter la contrainte CHECK
        cursor.execute("""
            ALTER TABLE alerts ADD CONSTRAINT chk_detected_domain_not_empty 
            CHECK (detected_domain IS NOT NULL AND detected_domain != '');
        """)
        
        conn.commit()
        logging.info("✅ Contraintes d'unicité ajoutées")
        
    except psycopg2.errors.DuplicateObject:
        logging.info("ℹ️  Les contraintes existent déjà")
        conn.rollback()
    except Exception as e:
        logging.error(f"Erreur lors de l'ajout des contraintes: {e}")
        conn.rollback()

def main():
    """Fonction principale"""
    print("🧹 Script de nettoyage sécurisé des doublons")
    print("=" * 50)
    
    # Demander confirmation
    response = input("⚠️  Voulez-vous continuer avec le nettoyage? (y/N): ")
    if response.lower() != 'y':
        print("❌ Opération annulée")
        sys.exit(0)
    
    conn = get_db_connection()
    
    try:
        # 1. Sauvegarde
        print("\n📦 Étape 1: Sauvegarde des doublons...")
        backup_table, backup_count = backup_duplicates(conn)
        
        # 2. Suppression
        print("\n🗑️  Étape 2: Suppression des doublons...")
        deleted_count = remove_duplicates(conn)
        
        # 3. Contraintes
        print("\n🔒 Étape 3: Ajout des contraintes d'unicité...")
        add_unique_constraint(conn)
        
        print(f"\n✅ Nettoyage terminé!")
        print(f"   - Doublons sauvegardés: {backup_count}")
        print(f"   - Doublons supprimés: {deleted_count}")
        print(f"   - Table de sauvegarde: {backup_table}")
        print(f"   - Contraintes ajoutées pour éviter les futurs doublons")
        
    except Exception as e:
        logging.error(f"Erreur durant le nettoyage: {e}")
        conn.rollback()
    finally:
        conn.close()

if __name__ == "__main__":
    main()