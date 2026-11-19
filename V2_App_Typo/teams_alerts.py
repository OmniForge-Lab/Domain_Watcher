#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import json
import requests
import logging
from datetime import datetime
from teams_config import TEAMS_CONFIG

# Configuration du logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger('teams_alerts')

def send_teams_alert(alert_data, alert_type="high_risk"):
    """
    Envoie une alerte via Power Automate (HTTP request) ou directement à Teams via webhook selon la configuration.
    
    Args:
        alert_data (dict): Données de l'alerte
        alert_type (str): Type d'alerte (high_risk, new_domain)
    
    Returns:
        bool: True si l'envoi a réussi, False sinon
    """
    try:
        # Vérifier si les alertes sont activées
        if not TEAMS_CONFIG.get('enabled', False):
            logger.info("Les alertes Teams/Power Automate sont désactivées dans la configuration")
            return False
        
        # Choisir la cible d'envoi en fonction de la configuration
        use_power_automate = TEAMS_CONFIG.get('use_power_automate', False)
        
        if use_power_automate:
            # Envoi vers Power Automate (déclencheur HTTP)
            flow_url = TEAMS_CONFIG.get('flow_urls', {}).get(alert_type)
            if not flow_url:
                logger.error(f"URL de flux Power Automate non configurée pour le type d'alerte: {alert_type}")
                return False
            
            payload = {
                "type": alert_type,
                "title": "Alerte typosquatting",
                "detected_domain": alert_data.get('detected_domain'),
                "original_domain": alert_data.get('original_domain'),
                "risk_score": alert_data.get('risk_score'),
                "risk_level": alert_data.get('risk_level'),
                "recommended_action": alert_data.get('recommended_action'),
                "alert_id": alert_data.get('id'),
                "link": f"{TEAMS_CONFIG.get('app_url', '')}/alert/{alert_data.get('id', '')}",
                "timestamp": datetime.now().isoformat()
            }
            
            response = requests.post(
                flow_url,
                headers={"Content-Type": "application/json"},
                data=json.dumps(payload)
            )
            
            if response.ok:
                logger.info(f"Alerte Power Automate envoyée: {alert_data.get('detected_domain')}")
                return True
            else:
                logger.error(f"Échec envoi Power Automate: {response.status_code} - {response.text}")
                return False
        else:
            # Envoi direct vers Teams via webhook
            webhook_url = TEAMS_CONFIG.get('webhook_urls', {}).get(alert_type)
            if not webhook_url:
                logger.error(f"URL de webhook non configurée pour le type d'alerte: {alert_type}")
                return False
            
            card = create_teams_card(alert_data, alert_type)
            response = requests.post(
                webhook_url,
                headers={"Content-Type": "application/json"},
                data=json.dumps(card)
            )
            
            if response.status_code == 200:
                logger.info(f"Alerte Teams envoyée avec succès: {alert_data.get('detected_domain')}")
                return True
            else:
                logger.error(f"Échec de l'envoi de l'alerte Teams: {response.status_code} - {response.text}")
                return False
            
    except Exception as e:
        logger.error(f"Erreur lors de l'envoi de l'alerte: {str(e)}")
        return False

def create_teams_card(alert_data, alert_type):
    """
    Crée une carte adaptative pour Microsoft Teams
    
    Args:
        alert_data (dict): Données de l'alerte
        alert_type (str): Type d'alerte
    
    Returns:
        dict: Carte adaptative au format JSON
    """
    # Déterminer le titre et la couleur selon le type d'alerte
    if alert_type == "high_risk":
        title = "🚨 Alerte de typosquatting à haut risque"
        theme_color = "FF0000"  # Rouge
    elif alert_type == "new_domain":
        title = "🔔 Nouveau domaine de typosquatting détecté"
        theme_color = "FFA500"  # Orange
    else:
        title = "ℹ️ Alerte de typosquatting"
        theme_color = "0078D7"  # Bleu
    
    # Formater la date de détection
    detection_date = alert_data.get('detection_date')
    if detection_date:
        if isinstance(detection_date, str):
            formatted_date = detection_date
        else:
            formatted_date = detection_date.strftime("%d/%m/%Y %H:%M")
    else:
        formatted_date = datetime.now().strftime("%d/%m/%Y %H:%M")
    
    # Créer la carte adaptative
    card = {
        "@type": "MessageCard",
        "@context": "http://schema.org/extensions",
        "themeColor": theme_color,
        "summary": title,
        "sections": [
            {
                "activityTitle": title,
                "activitySubtitle": f"Détecté le {formatted_date}",
                "facts": [
                    {
                        "name": "Domaine détecté",
                        "value": alert_data.get('detected_domain', 'N/A')
                    },
                    {
                        "name": "Domaine original",
                        "value": alert_data.get('original_domain', 'N/A')
                    },
                    {
                        "name": "Score de risque",
                        "value": f"{alert_data.get('risk_score', 0)}/100"
                    },
                    {
                        "name": "Adresse IP",
                        "value": alert_data.get('dns_a', 'Non disponible')
                    },
                    {
                        "name": "Registrar",
                        "value": alert_data.get('whois_registrar', 'Non disponible')
                    }
                ],
                "markdown": True
            }
        ],
        "potentialAction": [
            {
                "@type": "OpenUri",
                "name": "Voir dans l'application",
                "targets": [
                    {
                        "os": "default",
                        "uri": f"{TEAMS_CONFIG.get('app_url', '')}/alert/{alert_data.get('id', '')}"
                    }
                ]
            }
        ]
    }
    
    return card

def send_high_risk_alert(alert_data):
    """
    Envoie une alerte pour un domaine à haut risque
    
    Args:
        alert_data (dict): Données de l'alerte
    
    Returns:
        bool: True si l'envoi a réussi, False sinon
    """
    return send_teams_alert(alert_data, "high_risk")

def send_new_domain_alert(alert_data):
    """
    Envoie une alerte pour un nouveau domaine détecté
    
    Args:
        alert_data (dict): Données de l'alerte
    
    Returns:
        bool: True si l'envoi a réussi, False sinon
    """
    return send_teams_alert(alert_data, "new_domain")