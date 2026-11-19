#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import psycopg2
import requests
import socket
import logging
import time
from psycopg2.extras import DictCursor

# Configuration de la journalisation
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger('update_domain_info')

# Configuration de la base de données
DB_CONFIG = {
    'dbname': 'typoscan',
    'user': 'typo_user',
    'password': 'typo_pass',
    'host': 'localhost',
    'port': '5432'
}

# Configuration de l'API WHOIS
WHOIS_API_KEY = 'PSRd0xyGU6GtI4tkQOzFX3XqdKjIFD0T'
WHOIS_API_URL = 'https://api.apilayer.com/whois/query'

def get_db_connection():
    """Établit une connexion à la base de données."""
    try:
        conn = psycopg2.connect(**DB_CONFIG)
        return conn
    except Exception as e:
        logger.error(f"Erreur de connexion à la base de données: {e}")
        return None

def get_domain_ip(domain):
    """Récupère l'adresse IP d'un domaine via DNS."""
    try:
        ip = socket.gethostbyname(domain)
        return ip
    except socket.gaierror:
        logger.warning(f"Impossible de résoudre l'IP pour le domaine: {domain}")
        return None
    except Exception as e:
        logger.error(f"Erreur lors de la résolution DNS pour {domain}: {e}")
        return None

def get_domain_whois(domain):
    """Récupère les informations WHOIS d'un domaine via l'API."""
    try:
        headers = {'apikey': WHOIS_API_KEY}
        response = requests.get(f"{WHOIS_API_URL}?domain={domain}", headers=headers)
        response.raise_for_status()
        whois_data = response.json()
        
        registrar = whois_data.get('registrar', {}).get('name', '')
        creation_date = whois_data.get('created_date', '')
        
        return {
            'registrar': registrar,
            'created_date': creation_date
        }
    except requests.exceptions.RequestException as e:
        logger.error(f"Erreur lors de la requête WHOIS pour {domain}: {e}")
        return None
    except Exception as e:
        logger.error(f"Erreur lors du traitement WHOIS pour {domain}: {e}")
        return None

def update_alert_info(alert_id, dns_a=None, whois_registrar=None, whois_created=None):
    """Met à jour les informations d'une alerte dans la base de données."""
    conn = get_db_connection()
    if not conn:
        return False
    
    try:
        cursor = conn.cursor()
        
        # Construire la requête de mise à jour dynamiquement
        update_fields = []
        params = []
        
        if dns_a:
            update_fields.append("dns_a = %s")
            params.append(dns_a)
        
        if whois_registrar:
            update_fields.append("whois_registrar = %s")
            params.append(whois_registrar)
        
        if whois_created:
            update_fields.append("whois_created = %s")
            params.append(whois_created)
        
        if not update_fields:
            logger.warning(f"Aucune information à mettre à jour pour l'alerte {alert_id}")
            return False
        
        # Ajouter l'ID de l'alerte aux paramètres
        params.append(alert_id)
        
        # Exécuter la requête
        query = f"UPDATE alerts SET {', '.join(update_fields)} WHERE id = %s"
        cursor.execute(query, params)
        
        # Valider les modifications
        conn.commit()
        
        # Vérifier si la mise à jour a réussi
        if cursor.rowcount > 0:
            logger.info(f"Alerte {alert_id} mise à jour avec succès")
            return True
        else:
            logger.warning(f"Aucune alerte trouvée avec l'ID {alert_id}")
            return False
    
    except Exception as e:
        logger.error(f"Erreur lors de la mise à jour de l'alerte {alert_id}: {e}")
        conn.rollback()
        return False
    finally:
        conn.close()

def process_alerts_without_info(limit=50):
    """Traite les alertes qui n'ont pas d'informations DNS ou WHOIS."""
    conn = get_db_connection()
    if not conn:
        return
    
    try:
        cursor = conn.cursor(cursor_factory=DictCursor)
        
        # Récupérer les alertes sans informations DNS ou WHOIS
        cursor.execute("""
            SELECT id, detected_domain, dns_a, whois_registrar, whois_created
            FROM alerts
            WHERE (dns_a IS NULL OR dns_a = '' OR whois_registrar IS NULL OR whois_registrar = '')
            ORDER BY detection_date DESC
            LIMIT %s
        """, (limit,))
        
        alerts = cursor.fetchall()
        logger.info(f"Traitement de {len(alerts)} alertes sans informations complètes")
        
        for alert in alerts:
            alert_id = alert['id']
            domain = alert['detected_domain']
            
            # Récupérer l'IP si nécessaire
            dns_a = None
            if not alert['dns_a']:
                dns_a = get_domain_ip(domain)
                logger.info(f"IP récupérée pour {domain}: {dns_a}")
                time.sleep(0.5)  # Pause pour éviter de surcharger les serveurs DNS
            
            # Récupérer les informations WHOIS si nécessaires
            whois_registrar = None
            whois_created = None
            if not alert['whois_registrar']:
                whois_data = get_domain_whois(domain)
                if whois_data:
                    whois_registrar = whois_data.get('registrar')
                    whois_created = whois_data.get('created_date')
                    logger.info(f"Informations WHOIS récupérées pour {domain}: {whois_registrar}, {whois_created}")
                time.sleep(1)  # Pause pour respecter les limites de l'API
            
            # Mettre à jour l'alerte
            if dns_a or whois_registrar or whois_created:
                update_alert_info(alert_id, dns_a, whois_registrar, whois_created)
    
    except Exception as e:
        logger.error(f"Erreur lors du traitement des alertes: {e}")
    finally:
        conn.close()

if __name__ == "__main__":
    logger.info("Démarrage de la mise à jour des informations de domaine")
    process_alerts_without_info()
    logger.info("Mise à jour terminée")