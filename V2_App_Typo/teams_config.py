#!/usr/bin/env python3
# -*- coding: utf-8 -*-

# Configuration pour l'intégration Microsoft Teams
TEAMS_CONFIG = {
    # Activer/désactiver les alertes Teams
    'enabled': True,
    
    # URL de l'application (pour les liens dans les cartes adaptatives)
    'app_url': 'http://172.29.20.116:8000',
    
    # URLs des webhooks Teams (à remplacer par vos propres webhooks)
    'webhook_urls': {
        'high_risk': 'https://outlook.office.com/webhook/your-webhook-url-for-high-risk',
        'new_domain': 'https://outlook.office.com/webhook/your-webhook-url-for-new-domains'
    },

    # Utiliser Power Automate (HTTP Request trigger) au lieu des webhooks Teams
    'use_power_automate': True,

    # URLs des flux Power Automate (déclencheur "When an HTTP request is received")
    'flow_urls': {
        'high_risk': 'https://your-power-automate-flow-url-for-high-risk',
        'new_domain': 'https://your-power-automate-flow-url-for-new-domains'
    },
    
    # Seuil de score pour les alertes à haut risque
    'high_risk_threshold': 70,
    
    # Configuration des notifications
    'notifications': {
        'send_on_new_domain': True,
        'send_on_high_risk': True,
        'send_on_status_change': False
    }
}