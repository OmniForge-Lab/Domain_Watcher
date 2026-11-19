# Configuration du système de détection de typosquatting

# États des alertes
ALERT_STATES = {
    # États actifs - nécessitent une surveillance active
    'nouveau': {
        'label': 'Nouveau',
        'description': 'Domaine détecté récemment, analyse en cours',
        'color': 'warning',
        'priority': 1,
        'auto_transition': True,
        'max_duration_days': 7
    },
    'investigating': {
        'label': 'En investigation',
        'description': 'Analyse approfondie en cours',
        'color': 'info',
        'priority': 2,
        'auto_transition': False,
        'max_duration_days': 30
    },
    'monitoring': {
        'label': 'Surveillance',
        'description': 'Domaine sous surveillance continue',
        'color': 'secondary',
        'priority': 3,
        'auto_transition': False,
        'max_duration_days': 90
    },
    
    # États d'intervention - nécessitent une action
    'action_required': {
        'label': 'Action requise',
        'description': 'Intervention manuelle nécessaire',
        'color': 'danger',
        'priority': 0,
        'auto_transition': False,
        'max_duration_days': 1
    },
    'escalated': {
        'label': 'Escaladé',
        'description': 'Escaladé vers l\'équipe sécurité',
        'color': 'danger',
        'priority': 0,
        'auto_transition': False,
        'max_duration_days': 3
    },
    
    # États passifs - surveillance réduite
    'legitimate': {
        'label': 'Légitime',
        'description': 'Domaine confirmé comme légitime',
        'color': 'success',
        'priority': 5,
        'auto_transition': False,
        'max_duration_days': None
    },
    'parked': {
        'label': 'Parqué',
        'description': 'Domaine parqué, risque faible',
        'color': 'light',
        'priority': 4,
        'auto_transition': True,
        'max_duration_days': 180
    },
    'expired': {
        'label': 'Expiré',
        'description': 'Domaine expiré',
        'color': 'light',
        'priority': 6,
        'auto_transition': True,
        'max_duration_days': None
    },
    
    # États finaux - archivés
    'resolved': {
        'label': 'Résolu',
        'description': 'Problème résolu avec succès',
        'color': 'success',
        'priority': 7,
        'auto_transition': False,
        'max_duration_days': None
    },
    'false_positive': {
        'label': 'Faux positif',
        'description': 'Alerte confirmée comme fausse',
        'color': 'muted',
        'priority': 8,
        'auto_transition': False,
        'max_duration_days': None
    },
    'blocked': {
        'label': 'Bloqué',
        'description': 'Domaine bloqué avec succès',
        'color': 'dark',
        'priority': 7,
        'auto_transition': False,
        'max_duration_days': None
    }
}

# Configuration du système de scoring
SCORING_CONFIG = {
    'weights': {
        'similarity': 0.40,  # 40% - Similarité avec le domaine original
        'domain_age': 0.25,  # 25% - Âge du domaine
        'geolocation': 0.15, # 15% - Géolocalisation
        'ssl_cert': 0.10,    # 10% - Certificat SSL
        'reputation': 0.10   # 10% - Réputation VirusTotal
    },
    
    'thresholds': {
        'low_risk': 30,      # Score < 30 : Risque faible
        'medium_risk': 70,   # Score 30-70 : Risque moyen
        'high_risk': 100     # Score > 70 : Risque élevé
    },
    
    'intervention_thresholds': {
        'passive_monitoring': 30,    # < 30 : Surveillance passive
        'moderate_alert': 70,        # 30-70 : Alerte modérée
        'immediate_action': 70       # > 70 : Action immédiate
    }
}

# Configuration de la similarité
SIMILARITY_CONFIG = {
    'levenshtein_thresholds': {
        'very_high': 1,  # Distance <= 1 : Très haute similarité (score 90-100)
        'high': 2,       # Distance <= 2 : Haute similarité (score 70-89)
        'medium': 3,     # Distance <= 3 : Similarité moyenne (score 40-69)
        'low': 4         # Distance > 3 : Faible similarité (score 0-39)
    },
    'scoring': {
        'very_high': (90, 100),
        'high': (70, 89),
        'medium': (40, 69),
        'low': (0, 39)
    }
}

# Configuration de l'âge du domaine
DOMAIN_AGE_CONFIG = {
    'thresholds_days': {
        'very_new': 30,      # < 30 jours : Très récent (score 80-100)
        'new': 180,          # < 180 jours : Récent (score 50-79)
        'established': 365,  # < 1 an : Établi (score 20-49)
        'old': float('inf') # > 1 an : Ancien (score 0-19)
    },
    'scoring': {
        'very_new': (80, 100),
        'new': (50, 79),
        'established': (20, 49),
        'old': (0, 19)
    }
}

# Configuration de géolocalisation
GEOLOCATION_CONFIG = {
    'risk_countries': {
        'high': ['CN', 'RU', 'KP', 'IR'],  # Pays à haut risque
        'medium': ['PK', 'BD', 'NG', 'ID'], # Pays à risque moyen
        'low': ['US', 'CA', 'GB', 'FR', 'DE', 'AU', 'JP']  # Pays à faible risque
    },
    'scoring': {
        'high': (70, 100),
        'medium': (40, 69),
        'low': (0, 39),
        'unknown': (50, 50)  # Score par défaut si pays inconnu
    }
}

# Configuration SSL
SSL_CONFIG = {
    'scoring': {
        'valid': (0, 20),      # Certificat valide : faible risque
        'self_signed': (40, 60), # Auto-signé : risque moyen
        'expired': (60, 80),   # Expiré : risque élevé
        'invalid': (70, 90),   # Invalide : très haut risque
        'none': (80, 100)      # Pas de SSL : risque maximal
    }
}

# Configuration VirusTotal
VIRUSTOTAL_CONFIG = {
    'scoring': {
        'clean': (0, 10),        # Aucune détection
        'suspicious': (30, 50),  # 1-2 détections
        'malicious': (80, 100)   # 3+ détections
    },
    'thresholds': {
        'suspicious': 2,
        'malicious': 3
    }
}

# Configuration des notifications
NOTIFICATION_CONFIG = {
    'email': {
        'enabled': True,
        'smtp_server': 'smtp.company.com',
        'smtp_port': 587,
        'recipients': ['security@company.com']
    },
    'triggers': {
        'high_risk_score': 70,
        'new_domain_detection': True,
        'state_change_to_malicious': True
    }
}

# Configuration de la surveillance automatique
MONITORING_CONFIG = {
    'auto_transitions': {
        'nouveau_to_monitoring': {
            'condition': 'score < 30 and age > 7',
            'enabled': True
        },
        'monitoring_to_legitimate': {
            'condition': 'score < 20 and age > 90 and no_changes',
            'enabled': True
        },
        'parked_to_expired': {
            'condition': 'domain_expired',
            'enabled': True
        }
    },
    'check_intervals': {
        'nouveau': 24,        # Vérifier toutes les 24h
        'investigating': 12,  # Vérifier toutes les 12h
        'monitoring': 168,    # Vérifier toutes les semaines
        'action_required': 1  # Vérifier toutes les heures
    }
}

# Configuration des APIs externes
API_CONFIG = {
    'rate_limits': {
        'whois': {'requests_per_minute': 60},
        'virustotal': {'requests_per_minute': 4},
        'geolocation': {'requests_per_minute': 100}
    },
    'timeouts': {
        'whois': 10,
        'virustotal': 15,
        'geolocation': 5,
        'dns': 5,
        'ssl': 10
    },
    'retry_config': {
        'max_retries': 3,
        'backoff_factor': 2
    }
}