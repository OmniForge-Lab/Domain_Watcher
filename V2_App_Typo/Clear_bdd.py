import psycopg2
import logging

# Configuration du logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('clear_database.log'),
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

def get_all_tables(cursor):
    """
    Récupère la liste de toutes les tables de la base de données
    (exclut les tables système)
    """
    cursor.execute("""
        SELECT table_name 
        FROM information_schema.tables 
        WHERE table_schema = 'public' 
        AND table_type = 'BASE TABLE'
        ORDER BY table_name;
    """)
    return [row[0] for row in cursor.fetchall()]

def get_table_row_count(cursor, table_name):
    """
    Compte le nombre de lignes dans une table
    """
    try:
        cursor.execute(f"SELECT COUNT(*) FROM {table_name}")
        return cursor.fetchone()[0]
    except Exception as e:
        logger.warning(f"Impossible de compter les lignes de {table_name}: {e}")
        return 0

def truncate_table(cursor, table_name):
    """
    Vide une table en utilisant TRUNCATE
    """
    try:
        cursor.execute(f"TRUNCATE TABLE {table_name} RESTART IDENTITY CASCADE")
        logger.info(f"Table {table_name} vidée avec succès")
        return True
    except Exception as e:
        logger.error(f"Erreur lors du vidage de {table_name}: {e}")
        return False

def get_table_dependencies(cursor):
    """
    Récupère l'ordre des tables - méthode simplifiée
    """
    try:
        # Essayer une approche simple : tables référencées en premier
        cursor.execute("""
            SELECT DISTINCT ccu.table_name as referenced_table
            FROM information_schema.table_constraints tc
            JOIN information_schema.key_column_usage kcu 
                ON tc.constraint_name = kcu.constraint_name
            JOIN information_schema.constraint_column_usage ccu 
                ON ccu.constraint_name = tc.constraint_name
            WHERE tc.constraint_type = 'FOREIGN KEY'
            AND tc.table_schema = 'public'
            ORDER BY ccu.table_name;
        """)
        referenced_tables = [row[0] for row in cursor.fetchall()]
        
        # Puis toutes les autres tables
        cursor.execute("""
            SELECT table_name 
            FROM information_schema.tables 
            WHERE table_schema = 'public' 
            AND table_type = 'BASE TABLE'
            ORDER BY table_name;
        """)
        all_tables = [row[0] for row in cursor.fetchall()]
        
        # Tables qui ne sont pas référencées (peuvent être vidées en dernier)
        other_tables = [t for t in all_tables if t not in referenced_tables]
        
        # Ordre : tables référencées d'abord, puis les autres
        return referenced_tables + other_tables
        
    except Exception as e:
        logger.warning(f"Impossible de déterminer l'ordre des dépendances: {e}")
        return []

def delete_table_data(cursor, table_name):
    """
    Vide une table en utilisant DELETE (plus lent mais sans problème de privilèges)
    """
    try:
        cursor.execute(f"DELETE FROM {table_name}")
        deleted_count = cursor.rowcount
        logger.info(f"Table {table_name}: {deleted_count} lignes supprimées")
        return True
    except Exception as e:
        logger.error(f"Erreur lors du vidage de {table_name}: {e}")
        return False

def clear_database_interactive():
    """
    Vide la base de données de manière interactive avec confirmation
    """
    try:
        with psycopg2.connect(**DB_CONFIG) as conn:
            with conn.cursor() as cursor:
                # Récupérer toutes les tables
                tables = get_all_tables(cursor)
                
                if not tables:
                    logger.info("Aucune table trouvée dans la base de données")
                    return
                
                logger.info(f"Tables trouvées dans la base de données:")
                total_rows = 0
                table_info = []
                
                for table in tables:
                    row_count = get_table_row_count(cursor, table)
                    total_rows += row_count
                    table_info.append((table, row_count))
                    logger.info(f"  - {table}: {row_count} lignes")
                
                logger.info(f"\nTotal: {len(tables)} tables, {total_rows} lignes")
                
                if total_rows == 0:
                    logger.info("La base de données est déjà vide")
                    return
                
                # Demander confirmation
                print("\n" + "="*50)
                print("ATTENTION: Cette opération va SUPPRIMER TOUTES LES DONNÉES")
                print("Les structures des tables seront conservées")
                print("="*50)
                
                response = input(f"\nVoulez-vous vraiment vider {len(tables)} tables ({total_rows} lignes) ? [oui/NON]: ").strip().lower()
                
                if response not in ['oui', 'o', 'yes', 'y']:
                    logger.info("Opération annulée par l'utilisateur")
                    return
                
                # Deuxième confirmation pour être sûr
                response2 = input("Êtes-vous ABSOLUMENT sûr ? Tapez 'VIDER' pour confirmer: ").strip()
                
                if response2 != 'VIDER':
                    logger.info("Opération annulée - confirmation non reçue")
                    return
                
                # Procéder au vidage
                logger.info("\nDébut du vidage de la base de données...")
                
                # Méthode simple : utiliser TRUNCATE avec CASCADE
                success_count = 0
                failed_tables = []
                
                for table_name, row_count in table_info:
                    if row_count > 0:
                        logger.info(f"Vidage de {table_name} ({row_count} lignes)...")
                        
                        # Essayer TRUNCATE avec CASCADE d'abord
                        try:
                            cursor.execute(f"TRUNCATE TABLE {table_name} CASCADE")
                            logger.info(f"Table {table_name} vidée avec TRUNCATE CASCADE")
                            success_count += 1
                        except Exception as truncate_error:
                            logger.warning(f"TRUNCATE échoué pour {table_name}: {truncate_error}")
                            logger.info(f"Tentative avec DELETE pour {table_name}")
                            
                            # Fallback avec DELETE
                            if delete_table_data(cursor, table_name):
                                success_count += 1
                            else:
                                failed_tables.append(table_name)
                    else:
                        logger.info(f"Table {table_name} déjà vide, ignorée")
                
                # Commit des changements
                conn.commit()
                
                # Résumé
                logger.info(f"\n=== RÉSUMÉ ===")
                logger.info(f"Tables vidées avec succès: {success_count}")
                if failed_tables:
                    logger.warning(f"Tables avec erreurs: {len(failed_tables)}")
                    for table in failed_tables:
                        logger.warning(f"  - {table}")
                else:
                    logger.info("Toutes les tables ont été vidées avec succès")
                
                logger.info("Base de données vidée avec succès!")
                
    except Exception as e:
        logger.error(f"Erreur de connexion à la base de données: {e}")

def clear_database_force():
    """
    Vide la base de données sans confirmation (pour automatisation)
    """
    try:
        with psycopg2.connect(**DB_CONFIG) as conn:
            with conn.cursor() as cursor:
                tables = get_all_tables(cursor)
                
                if not tables:
                    logger.info("Aucune table trouvée")
                    return
                
                logger.info(f"Vidage forcé de {len(tables)} tables...")
                
                # Vider toutes les tables avec CASCADE
                for table in tables:
                    try:
                        cursor.execute(f"TRUNCATE TABLE {table} CASCADE")
                        logger.info(f"Table {table} vidée avec TRUNCATE CASCADE")
                    except Exception as truncate_error:
                        logger.warning(f"TRUNCATE échoué pour {table}: {truncate_error}")
                        logger.info(f"Tentative avec DELETE pour {table}")
                        delete_table_data(cursor, table)
                
                conn.commit()
                logger.info("Base de données vidée avec succès (mode forcé)")
                
    except Exception as e:
        logger.error(f"Erreur lors du vidage forcé: {e}")

def reset_sequences():
    """
    Remet à zéro tous les compteurs de séquences (pour les ID auto-incrémentés)
    """
    try:
        with psycopg2.connect(**DB_CONFIG) as conn:
            with conn.cursor() as cursor:
                # Récupérer toutes les séquences
                cursor.execute("""
                    SELECT sequence_name 
                    FROM information_schema.sequences 
                    WHERE sequence_schema = 'public'
                """)
                sequences = [row[0] for row in cursor.fetchall()]
                
                logger.info(f"Remise à zéro de {len(sequences)} séquences...")
                
                for seq in sequences:
                    cursor.execute(f"ALTER SEQUENCE {seq} RESTART WITH 1")
                    logger.info(f"Séquence {seq} remise à 1")
                
                conn.commit()
                logger.info("Toutes les séquences ont été remises à zéro")
                
    except Exception as e:
        logger.error(f"Erreur lors de la remise à zéro des séquences: {e}")

def main():
    """
    Fonction principale avec options
    """
    import argparse
    
    parser = argparse.ArgumentParser(description='Vider la base de données PostgreSQL')
    parser.add_argument('--force', action='store_true', 
                       help='Vider sans demander de confirmation')
    parser.add_argument('--reset-sequences', action='store_true',
                       help='Remet aussi à zéro les compteurs de séquences')
    
    args = parser.parse_args()
    
    if args.force:
        logger.info("Mode forcé activé - aucune confirmation demandée")
        clear_database_force()
    else:
        clear_database_interactive()
    
    if args.reset_sequences:
        reset_sequences()

if __name__ == "__main__":
    main()