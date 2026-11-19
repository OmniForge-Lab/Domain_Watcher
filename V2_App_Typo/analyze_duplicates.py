#!/usr/bin/env python3
"""
Script pour analyser et identifier les doublons dans la base de données
"""

import psycopg2
from psycopg2.extras import DictCursor
from dotenv import load_dotenv
import os
import json

# Charger les variables d'environnement
load_dotenv()

DB_CONFIG = {
    'host': os.getenv('DB_HOST'),
    'database': os.getenv('DB_NAME'),
    'user': os.getenv('DB_USER'),
    'password': os.getenv('DB_PASS')
}

def analyze_duplicates():
    """Analyse les doublons dans la table alerts"""
    try:
        conn = psycopg2.connect(**DB_CONFIG)
        cursor = conn.cursor(cursor_factory=DictCursor)
        
        print("🔍 Analyse des doublons dans la table alerts...")
        
        # 1. Compter le nombre total d'alertes
        cursor.execute("SELECT COUNT(*) FROM alerts")
        total_alerts = cursor.fetchone()[0]
        print(f"📊 Total des alertes: {total_alerts}")
        
        # 2. Identifier les domaines en doublon
        cursor.execute("""
            SELECT detected_domain, COUNT(*) as count, 
                   MIN(id) as first_id, MAX(id) as last_id,
                   MIN(detection_date) as first_detection,
                   MAX(detection_date) as last_detection
            FROM alerts 
            GROUP BY detected_domain 
            HAVING COUNT(*) > 1 
            ORDER BY count DESC 
            LIMIT 20
        """)
        
        duplicates = cursor.fetchall()
        
        if duplicates:
            print(f"\n❌ Trouvé {len(duplicates)} domaines en doublon (top 20):")
            print("-" * 100)
            print(f"{'Domaine':<40} {'Nb':<5} {'Premier ID':<12} {'Dernier ID':<12} {'Première détection':<20} {'Dernière détection'}")
            print("-" * 100)
            
            total_duplicate_count = 0
            for dup in duplicates:
                total_duplicate_count += dup['count'] - 1  # -1 car on garde une occurrence
                print(f"{dup['detected_domain']:<40} {dup['count']:<5} {dup['first_id']:<12} {dup['last_id']:<12} {str(dup['first_detection'])[:19]:<20} {str(dup['last_detection'])[:19]}")
            
            print(f"\n📈 Nombre total d'alertes en doublon à supprimer: {total_duplicate_count}")
            
            # 3. Analyser les sources de duplication
            cursor.execute("""
                SELECT source, COUNT(*) as count
                FROM alerts a1
                WHERE EXISTS (
                    SELECT 1 FROM alerts a2 
                    WHERE a2.detected_domain = a1.detected_domain 
                    AND a2.id != a1.id
                )
                GROUP BY source
                ORDER BY count DESC
            """)
            
            sources = cursor.fetchall()
            if sources:
                print(f"\n📋 Sources des doublons:")
                for source in sources:
                    print(f"  - {source['source']}: {source['count']} alertes dupliquées")
            
            # 4. Analyser les doublons par watched_domain_id
            cursor.execute("""
                SELECT wd.domain as original_domain, a.detected_domain, COUNT(*) as count
                FROM alerts a
                JOIN watched_domains wd ON a.watched_domain_id = wd.id
                WHERE a.detected_domain IN (
                    SELECT detected_domain 
                    FROM alerts 
                    GROUP BY detected_domain 
                    HAVING COUNT(*) > 1
                )
                GROUP BY wd.domain, a.detected_domain
                HAVING COUNT(*) > 1
                ORDER BY count DESC
                LIMIT 10
            """)
            
            domain_duplicates = cursor.fetchall()
            if domain_duplicates:
                print(f"\n🎯 Doublons par domaine surveillé (top 10):")
                for dup in domain_duplicates:
                    print(f"  - {dup['original_domain']} -> {dup['detected_domain']}: {dup['count']} fois")
        
        else:
            print("✅ Aucun doublon trouvé dans la base de données!")
        
        # 5. Statistiques générales
        cursor.execute("""
            SELECT 
                COUNT(DISTINCT detected_domain) as unique_domains,
                COUNT(*) as total_alerts,
                COUNT(*) - COUNT(DISTINCT detected_domain) as duplicate_alerts
            FROM alerts
        """)
        
        stats = cursor.fetchone()
        print(f"\n📊 Statistiques générales:")
        print(f"  - Domaines uniques: {stats['unique_domains']}")
        print(f"  - Total alertes: {stats['total_alerts']}")
        print(f"  - Alertes en doublon: {stats['duplicate_alerts']}")
        
        if stats['duplicate_alerts'] > 0:
            percentage = (stats['duplicate_alerts'] / stats['total_alerts']) * 100
            print(f"  - Pourcentage de doublons: {percentage:.2f}%")
        
        cursor.close()
        conn.close()
        
        return len(duplicates) > 0
        
    except Exception as e:
        print(f"❌ Erreur lors de l'analyse: {e}")
        return False

def generate_cleanup_script():
    """Génère un script SQL pour nettoyer les doublons"""
    try:
        conn = psycopg2.connect(**DB_CONFIG)
        cursor = conn.cursor(cursor_factory=DictCursor)
        
        print("\n🛠️ Génération du script de nettoyage...")
        
        # Récupérer tous les doublons avec leurs IDs
        cursor.execute("""
            SELECT detected_domain, array_agg(id ORDER BY id) as ids
            FROM alerts 
            GROUP BY detected_domain 
            HAVING COUNT(*) > 1
        """)
        
        duplicates = cursor.fetchall()
        
        if duplicates:
            cleanup_script = "-- Script de nettoyage des doublons\n"
            cleanup_script += "-- Généré automatiquement\n\n"
            cleanup_script += "BEGIN;\n\n"
            
            total_to_delete = 0
            
            for dup in duplicates:
                domain = dup['detected_domain']
                ids = dup['ids']
                # Garder le premier ID, supprimer les autres
                ids_to_delete = ids[1:]  # Tous sauf le premier
                total_to_delete += len(ids_to_delete)
                
                if ids_to_delete:
                    cleanup_script += f"-- Supprimer les doublons pour: {domain}\n"
                    cleanup_script += f"DELETE FROM alerts WHERE id IN ({','.join(map(str, ids_to_delete))});\n\n"
            
            cleanup_script += f"-- Total d'alertes à supprimer: {total_to_delete}\n"
            cleanup_script += "COMMIT;\n"
            
            # Sauvegarder le script
            script_file = "cleanup_duplicates.sql"
            with open(script_file, 'w', encoding='utf-8') as f:
                f.write(cleanup_script)
            
            print(f"✅ Script de nettoyage généré: {script_file}")
            print(f"📝 {total_to_delete} alertes seront supprimées")
            print(f"⚠️  ATTENTION: Vérifiez le script avant de l'exécuter!")
            
        cursor.close()
        conn.close()
        
    except Exception as e:
        print(f"❌ Erreur lors de la génération du script: {e}")

if __name__ == "__main__":
    print("🔍 Analyse des doublons dans la base de données TypoScan")
    print("=" * 60)
    
    has_duplicates = analyze_duplicates()
    
    if has_duplicates:
        print("\n" + "=" * 60)
        response = input("Voulez-vous générer un script de nettoyage? (y/N): ")
        if response.lower() in ['y', 'yes', 'oui']:
            generate_cleanup_script()
    
    print("\n✅ Analyse terminée!")