from fastapi import FastAPI, Request, Depends, Form, HTTPException
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.templating import Jinja2Templates
from pydantic import BaseModel
import psycopg2
from psycopg2.extras import DictCursor
from dotenv import load_dotenv
import os
import subprocess
from datetime import datetime, timedelta
import requests
import json
import re
import ssl
import socket
import whois
import asyncio
from decimal import Decimal
from config import (
    ALERT_STATES, SCORING_CONFIG, SIMILARITY_CONFIG, 
    DOMAIN_AGE_CONFIG, GEOLOCATION_CONFIG, SSL_CONFIG, 
    VIRUSTOTAL_CONFIG, API_CONFIG
)

# Charger les variables d'environnement
load_dotenv()

app = FastAPI()

# Configuration Jinja2 pour le rendu HTML
templates = Jinja2Templates(directory="templates")

# Configuration de la base de données
DB_HOST = os.getenv('DB_HOST')
DB_NAME = os.getenv('DB_NAME')
DB_USER = os.getenv('DB_USER')
DB_PASS = os.getenv('DB_PASS')

def get_db_connection():
    return psycopg2.connect(
        host=DB_HOST,
        database=DB_NAME,
        user=DB_USER,
        password=DB_PASS
    )

# Fonction utilitaire pour calculer la distance de Levenshtein
def levenshtein_distance(s1, s2):
    """Calcule la distance de Levenshtein entre deux chaînes"""
    if len(s1) < len(s2):
        return levenshtein_distance(s2, s1)
    
    if len(s2) == 0:
        return len(s1)
    
    previous_row = list(range(len(s2) + 1))
    for i, c1 in enumerate(s1):
        current_row = [i + 1]
        for j, c2 in enumerate(s2):
            insertions = previous_row[j + 1] + 1
            deletions = current_row[j] + 1
            substitutions = previous_row[j] + (c1 != c2)
            current_row.append(min(insertions, deletions, substitutions))
        previous_row = current_row
    
    return previous_row[-1]

# Système de scoring
def calculate_similarity_score(levenshtein_distance):
    """Calcule le score de similarité basé sur la distance de Levenshtein"""
    if levenshtein_distance is None:
        return 50  # Score par défaut
    
    config = SIMILARITY_CONFIG['levenshtein_thresholds']
    scoring = SIMILARITY_CONFIG['scoring']
    
    # Calculer le score basé sur la distance
    if levenshtein_distance == 0:
        return 100  # Identique = score parfait
    elif levenshtein_distance <= config['very_high']:
        # Distance 1: score entre 90-100, proportionnel
        return 95  # Score élevé pour distance très faible
    elif levenshtein_distance <= config['high']:
        # Distance 2: score entre 70-89
        return 85  # Score bon pour distance faible
    elif levenshtein_distance <= config['medium']:
        # Distance 3: score entre 40-69
        return 60  # Score moyen
    else:
        # Distance > 3: score faible
        max_distance = min(levenshtein_distance, 10)  # Limiter à 10 pour éviter les scores négatifs
        return max(10, 50 - (max_distance * 5))  # Score décroissant avec la distance

def calculate_domain_age_score(creation_date):
    """Calcule le score basé sur l'âge du domaine"""
    if not creation_date:
        return 50  # Score par défaut
    
    try:
        if isinstance(creation_date, str):
            # Essayer différents formats de date
            for fmt in ['%Y-%m-%d', '%Y-%m-%dT%H:%M:%S', '%Y-%m-%d %H:%M:%S']:
                try:
                    creation_date = datetime.strptime(creation_date.split('T')[0], '%Y-%m-%d')
                    break
                except ValueError:
                    continue
        
        if isinstance(creation_date, datetime):
            age_days = (datetime.now() - creation_date).days
            
            config = DOMAIN_AGE_CONFIG['thresholds_days']
            
            # Calculer le score basé sur l'âge réel
            if age_days < config['very_new']:  # < 30 jours
                # Score élevé pour domaines très récents (risque élevé)
                return min(100, 80 + (30 - age_days))  # 80-100
            elif age_days < config['new']:  # < 180 jours
                # Score moyen-élevé pour domaines récents
                progress = (age_days - 30) / (180 - 30)  # 0 à 1
                return int(80 - (progress * 15))  # 80 à 65
            elif age_days < config['established']:  # < 365 jours
                # Score moyen pour domaines établis
                progress = (age_days - 180) / (365 - 180)  # 0 à 1
                return int(50 - (progress * 20))  # 50 à 30
            else:  # > 365 jours
                # Score faible pour domaines anciens (moins de risque)
                years = age_days / 365
                if years > 10:
                    return 5  # Très ancien = très faible risque
                else:
                    return max(5, int(25 - (years * 2)))  # 25 à 5
    except Exception:
        pass
    
    return 50  # Score par défaut en cas d'erreur

def calculate_geolocation_score(country_code):
    """Calcule le score basé sur la géolocalisation"""
    if not country_code:
        return 50  # Score par défaut
    
    country_code = country_code.upper()
    config = GEOLOCATION_CONFIG['risk_countries']
    
    # Scores spécifiques par pays pour plus de nuance
    country_scores = {
        # Pays à haut risque
        'CN': 85, 'RU': 80, 'KP': 95, 'IR': 90,
        # Pays à risque moyen
        'PK': 60, 'BD': 55, 'NG': 65, 'ID': 50,
        # Pays à faible risque
        'US': 25, 'CA': 20, 'GB': 15, 'FR': 10, 'DE': 12, 'AU': 18, 'JP': 22,
        # Autres pays européens sûrs
        'NL': 15, 'SE': 12, 'NO': 10, 'DK': 11, 'CH': 8, 'AT': 13,
        # Autres pays développés
        'KR': 25, 'SG': 20, 'NZ': 18
    }
    
    if country_code in country_scores:
        return country_scores[country_code]
    elif country_code in config['high']:
        return 85  # Score élevé par défaut pour pays à haut risque
    elif country_code in config['medium']:
        return 55  # Score moyen par défaut
    elif country_code in config['low']:
        return 20  # Score faible par défaut
    else:
        return 45  # Score par défaut pour pays inconnus

def calculate_ssl_score(ssl_status):
    """Calcule le score basé sur le statut SSL"""
    if not ssl_status:
        return 90  # Pas de SSL = risque élevé
    
    ssl_status = ssl_status.lower()
    
    # Scores nuancés selon le statut SSL
    if 'valid' in ssl_status:
        return 15  # Certificat valide = faible risque
    elif 'self' in ssl_status or 'auto' in ssl_status:
        return 50  # Auto-signé = risque moyen
    elif 'expired' in ssl_status:
        return 70  # Expiré = risque élevé
    elif 'invalid' in ssl_status:
        return 80  # Invalide = très haut risque
    else:
        return 90  # Statut inconnu = risque maximal

def calculate_reputation_score(virustotal_detections):
    """Calcule le score basé sur les détections VirusTotal"""
    if virustotal_detections is None:
        return 0  # Pas de données = pas de risque
    
    # Scores nuancés selon le nombre de détections
    if virustotal_detections == 0:
        return 5  # Aucune détection = très faible risque
    elif virustotal_detections == 1:
        return 25  # 1 détection = risque faible
    elif virustotal_detections == 2:
        return 45  # 2 détections = risque moyen
    elif virustotal_detections <= 5:
        return 70  # 3-5 détections = risque élevé
    else:
        # Plus de 5 détections = risque très élevé
        return min(95, 70 + (virustotal_detections - 5) * 5)

def calculate_overall_risk_score(similarity_distance=None, creation_date=None, 
                                country_code=None, ssl_status=None, 
                                virustotal_detections=None):
    """Calcule le score de risque global"""
    weights = SCORING_CONFIG['weights']
    
    # Calculer chaque composant
    similarity_score = calculate_similarity_score(similarity_distance)
    age_score = calculate_domain_age_score(creation_date)
    geo_score = calculate_geolocation_score(country_code)
    ssl_score = calculate_ssl_score(ssl_status)
    reputation_score = calculate_reputation_score(virustotal_detections)
    
    # Calculer le score pondéré
    overall_score = (
        similarity_score * weights['similarity'] +
        age_score * weights['domain_age'] +
        geo_score * weights['geolocation'] +
        ssl_score * weights['ssl_cert'] +
        reputation_score * weights['reputation']
    )
    
    return {
        'overall_score': round(overall_score, 2),
        'components': {
            'similarity': similarity_score,
            'domain_age': age_score,
            'geolocation': geo_score,
            'ssl': ssl_score,
            'reputation': reputation_score
        },
        'risk_level': get_risk_level(overall_score)
    }

def get_risk_level(score):
    """Détermine le niveau de risque basé sur le score"""
    thresholds = SCORING_CONFIG['thresholds']
    
    if score < thresholds['low_risk']:
        return 'LOW'
    elif score < thresholds['medium_risk']:
        return 'MEDIUM'
    else:
        return 'HIGH'

def get_recommended_action(score):
    """Recommande une action basée sur le score"""
    thresholds = SCORING_CONFIG['intervention_thresholds']
    
    if score < thresholds['passive_monitoring']:
        return 'passive_monitoring'
    elif score < thresholds['moderate_alert']:
        return 'moderate_alert'
    else:
        return 'immediate_action'

# Configuration des logs
LOGS_FILE = "logs.json"

# Classe pour les entrées de log
class LogEntry:
    def __init__(self, alert_id=None, domain="", action="", status="information", details=""):
        self.alert_id = alert_id
        self.domain = domain
        self.action = action
        self.status = status  # information, warning, error
        self.details = details
        self.timestamp = datetime.now()
    
    def to_dict(self):
        return {
            "alert_id": self.alert_id,
            "domain": self.domain,
            "action": self.action,
            "status": self.status,
            "details": self.details,
            "timestamp": self.timestamp.isoformat()
        }

# Fonctions de gestion des logs
def add_log_entry(log_entry):
    """Ajoute une entrée de log au fichier JSON"""
    try:
        # Lire les logs existants
        if os.path.exists(LOGS_FILE):
            with open(LOGS_FILE, 'r', encoding='utf-8') as f:
                logs = json.load(f)
        else:
            logs = []
        
        # Ajouter la nouvelle entrée
        logs.append(log_entry.to_dict())
        
        # Écrire dans le fichier
        with open(LOGS_FILE, 'w', encoding='utf-8') as f:
            json.dump(logs, f, ensure_ascii=False, indent=2)
            
    except Exception as e:
        print(f"Erreur lors de l'ajout du log: {e}")

def get_logs(domain_filter=None, alert_id_filter=None, status_filter=None, limit=100):
    """Récupère les logs avec filtres optionnels"""
    try:
        if not os.path.exists(LOGS_FILE):
            return []
        
        with open(LOGS_FILE, 'r', encoding='utf-8') as f:
            logs = json.load(f)
        
        # Appliquer les filtres
        filtered_logs = logs
        
        if domain_filter:
            filtered_logs = [log for log in filtered_logs if domain_filter.lower() in log.get('domain', '').lower()]
        
        if alert_id_filter:
            filtered_logs = [log for log in filtered_logs if log.get('alert_id') == alert_id_filter]
        
        if status_filter:
            filtered_logs = [log for log in filtered_logs if log.get('status') == status_filter]
        
        # Trier par timestamp (plus récent en premier)
        filtered_logs.sort(key=lambda x: x.get('timestamp', ''), reverse=True)
        
        # Limiter le nombre de résultats
        return filtered_logs[:limit]
        
    except Exception as e:
        print(f"Erreur lors de la lecture des logs: {e}")
        return []

def make_json_serializable(data):
    from datetime import datetime, date, time
    
    def convert_item(item):
        if isinstance(item, Decimal):
            return float(item)
        elif isinstance(item, (datetime, date, time)):
            return str(item)
        elif isinstance(item, dict):
            return {k: convert_item(v) for k, v in item.items()}
        elif isinstance(item, list):
            return [convert_item(i) for i in item]
        else:
            return item
    
    return convert_item(data)

# Schéma pour les entrées JSON
class WatchedDomain(BaseModel):
    domain: str
    distance_threshold: int = 1

class NewDomain(BaseModel):
    detected_domain: str
    original_domain: str

class AlertUpdate(BaseModel):
    id: int
    status: str

class AlertArchive(BaseModel):
    id: int
    reason: str = "manual_archive"
    archived_by: str = "dashboard_user"

class ScoringConfig(BaseModel):
    weights: dict
    thresholds: dict

class FeaturesConfig(BaseModel):
    features: dict

# Route index.html
@app.get("/", response_class=HTMLResponse)
async def index(request: Request):
    return templates.TemplateResponse("index.html", {"request": request})

# Route logs.html
@app.get("/logs", response_class=HTMLResponse)
async def logs_page(request: Request):
    return templates.TemplateResponse("logs.html", {"request": request})

# Route admin.html
@app.get("/admin", response_class=HTMLResponse)
async def admin_page(request: Request):
    return templates.TemplateResponse("admin.html", {"request": request})

# API endpoint pour récupérer les logs
@app.get("/api/logs")
async def get_logs_api(domain: str = None, alert_id: int = None, status: str = None, limit: int = 100):
    logs = get_logs(domain_filter=domain, alert_id_filter=alert_id, status_filter=status, limit=limit)
    return JSONResponse(content=logs)

# GET /watched_domains
@app.get("/watched_domains")
async def get_watched_domains():
    conn = get_db_connection()
    cursor = conn.cursor(cursor_factory=DictCursor)
    cursor.execute('SELECT * FROM watched_domains')
    domains = cursor.fetchall()
    cursor.close()
    conn.close()
    return JSONResponse([dict(domain) for domain in domains])

# POST /watched_domains
@app.post("/watched_domains")
async def add_watched_domain_and_alert(data: NewDomain):
    conn = get_db_connection()
    cursor = conn.cursor()
    
    try:
        # 1. Vérifier si le domaine d'origine existe déjà
        cursor.execute('SELECT id FROM watched_domains WHERE domain = %s', (data.original_domain,))
        watched_domain = cursor.fetchone()
        
        # Si le domaine d'origine n'existe pas, l'ajouter
        if not watched_domain:
            cursor.execute(
                'INSERT INTO watched_domains (domain, distance_threshold) VALUES (%s, %s) RETURNING id',
                (data.original_domain, 1)  # Valeur par défaut pour distance_threshold
            )
            watched_domain_id = cursor.fetchone()[0]
        else:
            watched_domain_id = watched_domain[0]
        
        # 2. Vérifier si le domaine suspect existe déjà
        cursor.execute('SELECT id FROM alerts WHERE detected_domain = %s', (data.detected_domain,))
        existing_alert = cursor.fetchone()
        
        if existing_alert:
            # Le domaine suspect existe déjà, retourner son ID
            alert_id = existing_alert[0]
        else:
            # Ajouter le nouveau domaine suspect comme alerte
            cursor.execute(
                '''
                INSERT INTO alerts 
                (detected_domain, watched_domain_id, detection_date, status) 
                VALUES (%s, %s, %s, %s) 
                RETURNING id
                ''',
                (data.detected_domain, watched_domain_id, datetime.now(), 'pending')
            )
            alert_id = cursor.fetchone()[0]
            
            # Ajouter une entrée de log
            log_entry = LogEntry(
                alert_id=alert_id,
                domain=data.detected_domain,
                action="add_domain",
                status="information",
                details="Domaine ajouté manuellement"
            )
            add_log_entry(log_entry)
        
        conn.commit()
        
        return JSONResponse({
            'success': True,
            'id': alert_id,
            'message': 'Domaine ajouté avec succès'
        })
    
    except Exception as e:
        conn.rollback()
        return JSONResponse({
            'success': False,
            'error': str(e)
        }, status_code=500)
    
    finally:
        cursor.close()
        conn.close()

@app.post("/add_watched_domain")
async def add_watched_domain(data: WatchedDomain):
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute(
        'INSERT INTO watched_domains (domain, distance_threshold) VALUES (%s, %s)',
        (data.domain, data.distance_threshold)
    )
    conn.commit()
    cursor.close()
    conn.close()
    return JSONResponse({'success': True})

# GET /alerts
from datetime import datetime
@app.get("/alerts")
async def get_alerts():
    conn = get_db_connection()
    cursor = conn.cursor(cursor_factory=DictCursor)
    cursor.execute('''
        SELECT a.*, wd.domain AS original_domain
        FROM alerts a
        JOIN watched_domains wd ON a.watched_domain_id = wd.id
        ORDER BY detection_date DESC
    ''')
    alerts = cursor.fetchall()
    cursor.close()
    conn.close()

    # Transformer chaque ligne en dict, avec conversion des dates
    serialized = []
    for alert in alerts:
        row = dict(alert)
        if isinstance(row.get("detection_date"), datetime):
            row["detection_date"] = row["detection_date"].isoformat()
        serialized.append(row)

    serialized = make_json_serializable(serialized)
    return JSONResponse(content=serialized)


# POST /update_alert_status
@app.post("/update_alert_status")
async def update_alert_status(data: AlertUpdate):
    conn = get_db_connection()
    cursor = conn.cursor(cursor_factory=DictCursor)
    
    # Récupérer les informations de l'alerte avant mise à jour
    cursor.execute('SELECT detected_domain, status FROM alerts WHERE id = %s', (data.id,))
    alert_info = cursor.fetchone()
    
    if alert_info:
        old_status = alert_info['status']
        domain = alert_info['detected_domain']
        
        # Mettre à jour le statut
        cursor.execute(
            'UPDATE alerts SET status = %s WHERE id = %s',
            (data.status, data.id)
        )
        
        # Mapper les statuts techniques vers les statuts de logging
        status_mapping = {
            'pending': 'information',
            'threat': 'warning',
            'phishing': 'warning',
            'suspicious': 'warning',
            'legitimate': 'information',
            'new': 'information'
        }
        
        log_status = status_mapping.get(data.status, data.status)
        
        # Ajouter une entrée de log
        log_entry = LogEntry(
            alert_id=data.id,
            domain=domain,
            action="update_status",
            status=log_status,
            details=f"Statut changé de '{old_status}' vers '{data.status}'"
        )
        add_log_entry(log_entry)
    
    conn.commit()
    cursor.close()
    conn.close()
    return JSONResponse({'success': True})

# GET /alert/{id}
@app.get("/alert/{id}")
async def get_alert(id: int):
    try:
        conn = get_db_connection()
        cursor = conn.cursor(cursor_factory=DictCursor)
        cursor.execute('''
            SELECT a.*, wd.domain AS original_domain
            FROM alerts a
            JOIN watched_domains wd ON a.watched_domain_id = wd.id
            WHERE a.id = %s
        ''', (id,))
        alert = cursor.fetchone()
        cursor.close()
        conn.close()

        if alert:
            alert_dict = dict(alert)
            alert_dict = make_json_serializable(alert_dict)
            return JSONResponse(content=alert_dict)
        else:
            raise HTTPException(status_code=404, detail="Alert not found")
            
    except Exception as e:
        # Log l'erreur si tu as un système de logging
        print(f"Erreur dans get_alert: {e}")
        raise HTTPException(status_code=500, detail="Erreur interne du serveur")

# POST /archive_alert - Archive une alerte vers alerts_history
@app.post("/archive_alert")
async def archive_alert(data: AlertArchive):
    """Archive une alerte en la déplaçant vers la table alerts_history"""
    try:
        conn = get_db_connection()
        cursor = conn.cursor(cursor_factory=DictCursor)
        
        # 1. Récupérer l'alerte à archiver
        cursor.execute('''
            SELECT * FROM alerts WHERE id = %s
        ''', (data.id,))
        alert = cursor.fetchone()
        
        if not alert:
            cursor.close()
            conn.close()
            raise HTTPException(status_code=404, detail="Alerte non trouvée")
        
        # 2. Insérer dans alerts_history
        cursor.execute('''
            INSERT INTO alerts_history (
                original_alert_id, source, watched_domain_id, detected_domain,
                lev_distance, dns_a, dns_mx, dns_ns, whois_created, whois_registrar,
                issuer, email, detection_date, original_status, comment, screenshot_path,
                risk_score, archived_reason, archived_by
            ) VALUES (
                %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s
            )
        ''', (
            alert['id'], alert['source'], alert['watched_domain_id'], alert['detected_domain'],
            alert['lev_distance'], alert['dns_a'], alert['dns_mx'], alert['dns_ns'],
            alert['whois_created'], alert['whois_registrar'], alert['issuer'], alert['email'],
            alert['detection_date'], alert['status'], alert['comment'], alert['screenshot_path'],
            alert.get('risk_score'), data.reason, data.archived_by
        ))
        
        # 3. Supprimer de la table alerts
        cursor.execute('DELETE FROM alerts WHERE id = %s', (data.id,))
        
        conn.commit()
        cursor.close()
        conn.close()
        
        # 4. Ajouter un log
        log_entry = LogEntry(
            alert_id=data.id,
            domain=alert['detected_domain'],
            action="archive",
            status="success",
            details=f"Alerte archivée: {data.reason}"
        )
        add_log_entry(log_entry)
        
        return JSONResponse({
            'success': True,
            'message': 'Alerte archivée avec succès',
            'archived_id': data.id
        })
        
    except Exception as e:
        print(f"Erreur dans archive_alert: {e}")
        raise HTTPException(status_code=500, detail="Erreur lors de l'archivage")

# GET /alerts_history - Consulter l'historique des alertes archivées
@app.get("/alerts_history")
async def get_alerts_history(limit: int = 100, offset: int = 0):
    """Récupère l'historique des alertes archivées"""
    try:
        conn = get_db_connection()
        cursor = conn.cursor(cursor_factory=DictCursor)
        
        cursor.execute('''
            SELECT ah.*, wd.domain AS original_domain
            FROM alerts_history ah
            LEFT JOIN watched_domains wd ON ah.watched_domain_id = wd.id
            ORDER BY ah.archived_date DESC
            LIMIT %s OFFSET %s
        ''', (limit, offset))
        
        history = cursor.fetchall()
        
        # Compter le total
        cursor.execute('SELECT COUNT(*) FROM alerts_history')
        total = cursor.fetchone()[0]
        
        cursor.close()
        conn.close()
        
        history_list = [make_json_serializable(dict(item)) for item in history]
        
        return JSONResponse({
            'history': history_list,
            'total': total,
            'limit': limit,
            'offset': offset
        })
        
    except Exception as e:
        print(f"Erreur dans get_alerts_history: {e}")
        raise HTTPException(status_code=500, detail="Erreur lors de la récupération de l'historique")

# GET /whois
@app.get("/whois")
async def whois_lookup(domain: str):
    # Vérifier si l'API WHOIS est activée
    if not is_feature_enabled('whois_api'):
        log_entry = LogEntry(
            domain=domain,
            action="whois_lookup",
            status="warning",
            details="API WHOIS désactivée dans la configuration"
        )
        add_log_entry(log_entry)
        
        return JSONResponse(content={
            "domain": domain,
            "error": "WHOIS API is disabled",
            "status": "feature_disabled"
        }, status_code=403)
    
    url = f"https://api.apilayer.com/whois/query?domain={domain}"

    headers = {
        'apikey': 'PSRd0xyGU6GtI4tkQOzFX3XqdKjIFD0T'
    }

    try:
        response = requests.get(url, headers=headers)
        response.raise_for_status()
        whois_info = response.json()
        
        # Mettre à jour les informations WHOIS dans la base de données
        conn = get_db_connection()
        cursor = conn.cursor()
        
        # Extraire les informations pertinentes
        registrar = whois_info.get('registrar', {}).get('name', '')
        creation_date = whois_info.get('created_date', '')
        
        # Mettre à jour l'alerte correspondante
        cursor.execute(
            'UPDATE alerts SET whois_registrar = %s, whois_created = %s WHERE detected_domain = %s',
            (registrar, creation_date, domain)
        )
        
        conn.commit()
        cursor.close()
        conn.close()
        
        return JSONResponse(content=whois_info)
    except requests.exceptions.RequestException as e:
        return JSONResponse(content={"error": str(e)}, status_code=500)

# GET /dns
@app.get("/dns")
async def dns_analysis(domain: str):
    try:
        import socket
        
        # Résolution DNS basique
        ip_address = socket.gethostbyname(domain)
        
        # Ajouter une entrée de log
        log_entry = LogEntry(
            domain=domain,
            action="dns_analysis",
            status="information",
            details=f"Analyse DNS réussie - IP: {ip_address}"
        )
        add_log_entry(log_entry)
        
        dns_info = {
            "domain": domain,
            "ip_address": ip_address,
            "analysis_time": datetime.now().isoformat(),
            "status": "resolved"
        }
        
        return JSONResponse(content=dns_info)
        
    except socket.gaierror as e:
        # Ajouter une entrée de log pour l'erreur
        log_entry = LogEntry(
            domain=domain,
            action="dns_analysis",
            status="warning",
            details=f"Échec de résolution DNS: {str(e)}"
        )
        add_log_entry(log_entry)
        
        return JSONResponse(content={
            "domain": domain,
            "error": f"DNS resolution failed: {str(e)}",
            "status": "failed"
        }, status_code=400)
    
    except Exception as e:
        # Ajouter une entrée de log pour l'erreur
        log_entry = LogEntry(
            domain=domain,
            action="dns_analysis",
            status="error",
            details=f"Erreur lors de l'analyse DNS: {str(e)}"
        )
        add_log_entry(log_entry)
        
        return JSONResponse(content={
            "domain": domain,
            "error": str(e),
            "status": "error"
        }, status_code=500)
    

# GET /ssl
@app.get("/ssl")
async def ssl_check(domain: str):
    try:
        # Nettoyer le domaine (enlever http/https si présent)
        clean_domain = domain.replace('http://', '').replace('https://', '').split('/')[0]
        
        # Fonction synchrone pour la vérification SSL
        def sync_ssl_check():
            context = ssl.create_default_context()
            with socket.create_connection((clean_domain, 443), timeout=8) as sock:
                with context.wrap_socket(sock, server_hostname=clean_domain) as ssock:
                    return ssock.getpeercert()
        
        # Exécuter la fonction synchrone de manière asynchrone avec timeout
        cert = await asyncio.wait_for(
            asyncio.get_event_loop().run_in_executor(None, sync_ssl_check),
            timeout=10.0  # Timeout total de 10 secondes
        )
        
        # Extraire les informations du certificat
        subject = dict(x[0] for x in cert['subject'])
        issuer = dict(x[0] for x in cert['issuer'])
        
        # Convertir les dates
        not_before = datetime.strptime(cert['notBefore'], '%b %d %H:%M:%S %Y %Z')
        not_after = datetime.strptime(cert['notAfter'], '%b %d %H:%M:%S %Y %Z')
        
        # Vérifier si le certificat est valide
        now = datetime.now()
        is_valid = not_before <= now <= not_after
        
        ssl_info = {
            "domain": clean_domain,
            "subject": subject.get('commonName', 'N/A'),
            "issuer": issuer.get('organizationName', 'N/A'),
            "valid_from": not_before.isoformat(),
            "valid_until": not_after.isoformat(),
            "is_valid": is_valid,
            "days_until_expiry": (not_after - now).days if is_valid else 0,
            "serial_number": cert.get('serialNumber', 'N/A'),
            "version": cert.get('version', 'N/A')
        }
        
        # Ajouter une entrée de log
        status = "information" if is_valid else "warning"
        details = f"Certificat SSL {'valide' if is_valid else 'invalide'} - Expire le {not_after.strftime('%Y-%m-%d')}"
        
        log_entry = LogEntry(
            domain=clean_domain,
            action="ssl_check",
            status=status,
            details=details
        )
        add_log_entry(log_entry)
        
        # Utiliser make_json_serializable pour éviter les erreurs de sérialisation
        ssl_info = make_json_serializable(ssl_info)
        return JSONResponse(content=ssl_info)
        
    except asyncio.TimeoutError:
        log_entry = LogEntry(
            domain=domain,
            action="ssl_check",
            status="warning",
            details="Timeout lors de la vérification SSL"
        )
        add_log_entry(log_entry)
        
        return JSONResponse(content={
            "domain": domain,
            "error": "Connection timeout",
            "status": "timeout"
        }, status_code=408)
        
    except socket.timeout:
        log_entry = LogEntry(
            domain=domain,
            action="ssl_check",
            status="warning",
            details="Timeout lors de la vérification SSL"
        )
        add_log_entry(log_entry)
        
        return JSONResponse(content={
            "domain": domain,
            "error": "Connection timeout",
            "status": "timeout"
        }, status_code=408)
        
    except socket.gaierror as e:
        log_entry = LogEntry(
            domain=domain,
            action="ssl_check",
            status="warning",
            details=f"Erreur DNS: {str(e)}"
        )
        add_log_entry(log_entry)
        
        return JSONResponse(content={
            "domain": domain,
            "error": f"DNS resolution failed: {str(e)}",
            "status": "dns_error"
        }, status_code=400)
        
    except ssl.SSLError as e:
        log_entry = LogEntry(
            domain=domain,
            action="ssl_check",
            status="warning",
            details=f"Erreur SSL: {str(e)}"
        )
        add_log_entry(log_entry)
        
        return JSONResponse(content={
            "domain": domain,
            "error": f"SSL Error: {str(e)}",
            "status": "ssl_error"
        }, status_code=400)
        
    except Exception as e:
        log_entry = LogEntry(
            domain=domain,
            action="ssl_check",
            status="error",
            details=f"Erreur lors de la vérification SSL: {str(e)}"
        )
        add_log_entry(log_entry)
        
        return JSONResponse(content={
            "domain": domain,
            "error": str(e),
            "status": "error"
        }, status_code=500)
    
# GET /screenshot
@app.get("/screenshot")
async def screenshot_capture(domain: str):
    import time
    time.sleep(1)
    
    screenshot_url = f"https://api.screenshotmachine.com/?key=0edfcc&url=http://{domain}&dimension=1024x768"
    
    screenshot_info = {
        "domain": domain, 
        "screenshot_url": screenshot_url,
        "capture_time": datetime.now().isoformat()
    }
    return JSONResponse(content=screenshot_info)

# GET /virus_total
@app.get("/virus_total")
async def virus_total_check(domain: str):
    # Vérifier si l'API VirusTotal est activée
    if not is_feature_enabled('virustotal_api'):
        log_entry = LogEntry(
            domain=domain,
            action="virus_total_check",
            status="warning",
            details="API VirusTotal désactivée dans la configuration"
        )
        add_log_entry(log_entry)
        
        return JSONResponse(content={
            "domain": domain,
            "error": "VirusTotal API is disabled",
            "status": "feature_disabled"
        }, status_code=403)
    
    try:
        import requests
        import base64
        
        # Clé API VirusTotal (à remplacer par une vraie clé)
        api_key = "f8d6da2a648961e08f9d9739678272268784a079a27a2affaa11b86de4adf511"
        
        if api_key == "YOUR_KEY_HERE":
            log_entry = LogEntry(
                domain=domain,
                action="virus_total_check",
                status="warning",
                details="Clé API VirusTotal non configurée"
            )
            add_log_entry(log_entry)
            
            return JSONResponse(content={
                "domain": domain,
                "error": "VirusTotal API key not configured",
                "status": "api_key_missing"
            }, status_code=400)
        
        # Encoder le domaine en base64 pour l'API VirusTotal
        domain_id = base64.urlsafe_b64encode(domain.encode()).decode().strip("=")
        
        # URL de l'API VirusTotal v3
        url = f"https://www.virustotal.com/api/v3/domains/{domain}"
        
        headers = {
            "x-apikey": api_key
        }
        
        # Faire la requête à l'API VirusTotal
        response = requests.get(url, headers=headers, timeout=30)
        
        if response.status_code == 200:
            data = response.json()
            
            # Extraire les informations pertinentes
            attributes = data.get('data', {}).get('attributes', {})
            last_analysis_stats = attributes.get('last_analysis_stats', {})
            
            vt_info = {
                "domain": domain,
                "reputation": attributes.get('reputation', 0),
                "malicious": last_analysis_stats.get('malicious', 0),
                "suspicious": last_analysis_stats.get('suspicious', 0),
                "clean": last_analysis_stats.get('harmless', 0),
                "undetected": last_analysis_stats.get('undetected', 0),
                "total_votes": sum(last_analysis_stats.values()),
                "categories": attributes.get('categories', {}),
                "creation_date": attributes.get('creation_date'),
                "last_modification_date": attributes.get('last_modification_date'),
                "analysis_date": datetime.now().isoformat()
            }
            
            # Déterminer le statut basé sur les résultats
            if last_analysis_stats.get('malicious', 0) > 0:
                status = "warning"
                details = f"Domaine détecté comme malveillant par {last_analysis_stats.get('malicious', 0)} moteurs"
            elif last_analysis_stats.get('suspicious', 0) > 0:
                status = "warning"
                details = f"Domaine détecté comme suspect par {last_analysis_stats.get('suspicious', 0)} moteurs"
            else:
                status = "information"
                details = f"Domaine analysé - Réputation: {attributes.get('reputation', 0)}"
            
            log_entry = LogEntry(
                domain=domain,
                action="virus_total_check",
                status=status,
                details=details
            )
            add_log_entry(log_entry)
            
            return JSONResponse(content=vt_info)
            
        elif response.status_code == 404:
            log_entry = LogEntry(
                domain=domain,
                action="virus_total_check",
                status="information",
                details="Domaine non trouvé dans VirusTotal"
            )
            add_log_entry(log_entry)
            
            return JSONResponse(content={
                "domain": domain,
                "error": "Domain not found in VirusTotal",
                "status": "not_found"
            }, status_code=404)
            
        else:
            log_entry = LogEntry(
                domain=domain,
                action="virus_total_check",
                status="error",
                details=f"Erreur API VirusTotal: {response.status_code}"
            )
            add_log_entry(log_entry)
            
            return JSONResponse(content={
                "domain": domain,
                "error": f"VirusTotal API error: {response.status_code}",
                "status": "api_error"
            }, status_code=response.status_code)
            
    except requests.exceptions.Timeout:
        log_entry = LogEntry(
            domain=domain,
            action="virus_total_check",
            status="warning",
            details="Timeout lors de la requête VirusTotal"
        )
        add_log_entry(log_entry)
        
        return JSONResponse(content={
            "domain": domain,
            "error": "Request timeout",
            "status": "timeout"
        }, status_code=408)
        
    except Exception as e:
        log_entry = LogEntry(
            domain=domain,
            action="virus_total_check",
            status="error",
            details=f"Erreur lors de la vérification VirusTotal: {str(e)}"
        )
        add_log_entry(log_entry)
        
        return JSONResponse(content={
            "domain": domain,
            "error": str(e),
            "status": "error"
        }, status_code=500)

# GET /similarity
@app.get("/similarity")
async def similarity_check(domain: str):
    conn = get_db_connection()
    cursor = conn.cursor(cursor_factory=DictCursor)
    cursor.execute('''
        SELECT wd.domain AS original_domain
        FROM alerts a
        JOIN watched_domains wd ON a.watched_domain_id = wd.id
        WHERE a.detected_domain = %s
        LIMIT 1
    ''', (domain,))
    result = cursor.fetchone()
    cursor.close()
    conn.close()
    
    original_domain = result['original_domain'] if result else ""
    
    from Levenshtein import distance
    similarity_score = distance(original_domain, domain) if original_domain else -1
    
    similarity_info = {
        "domain": domain, 
        "original_domain": original_domain,
        "similarity_info": {
            "levenshtein_distance": similarity_score,
            "is_similar": similarity_score <= 3 if similarity_score >= 0 else False
        }
    }
    return JSONResponse(content=similarity_info)

# GET /geolocation
@app.get("/geolocation")
async def geolocation_check(domain: str):
    # Vérifier si l'API de géolocalisation est activée
    if not is_feature_enabled('geolocation_api'):
        log_entry = LogEntry(
            domain=domain,
            action="geolocation_check",
            status="warning",
            details="API de géolocalisation désactivée dans la configuration"
        )
        add_log_entry(log_entry)
        
        return JSONResponse(content={
            "domain": domain,
            "error": "Geolocation API is disabled",
            "status": "feature_disabled"
        }, status_code=403)
    
    try:
        import requests
        import socket
        
        # Résoudre le domaine en adresse IP
        try:
            ip_address = socket.gethostbyname(domain)
        except socket.gaierror as e:
            log_entry = LogEntry(
                domain=domain,
                action="geolocation_check",
                status="warning",
                details=f"Impossible de résoudre le domaine: {str(e)}"
            )
            add_log_entry(log_entry)
            
            return JSONResponse(content={
                "domain": domain,
                "error": f"DNS resolution failed: {str(e)}",
                "status": "dns_failed"
            }, status_code=400)
        
        # Utiliser un service de géolocalisation gratuit (ip-api.com)
        geo_url = f"http://ip-api.com/json/{ip_address}"
        
        response = requests.get(geo_url, timeout=10)
        
        if response.status_code == 200:
            geo_data = response.json()
            
            if geo_data.get('status') == 'success':
                geo_info = {
                    "domain": domain,
                    "ip_address": ip_address,
                    "country": geo_data.get('country', 'Unknown'),
                    "country_code": geo_data.get('countryCode', 'Unknown'),
                    "region": geo_data.get('regionName', 'Unknown'),
                    "city": geo_data.get('city', 'Unknown'),
                    "latitude": geo_data.get('lat'),
                    "longitude": geo_data.get('lon'),
                    "timezone": geo_data.get('timezone', 'Unknown'),
                    "isp": geo_data.get('isp', 'Unknown'),
                    "organization": geo_data.get('org', 'Unknown'),
                    "as_number": geo_data.get('as', 'Unknown'),
                    "analysis_date": datetime.now().isoformat()
                }
                
                log_entry = LogEntry(
                    domain=domain,
                    action="geolocation_check",
                    status="information",
                    details=f"Géolocalisation réussie - Pays: {geo_data.get('country', 'Unknown')}, Ville: {geo_data.get('city', 'Unknown')}"
                )
                add_log_entry(log_entry)
                
                return JSONResponse(content=geo_info)
            else:
                log_entry = LogEntry(
                    domain=domain,
                    action="geolocation_check",
                    status="warning",
                    details=f"Échec de géolocalisation: {geo_data.get('message', 'Unknown error')}"
                )
                add_log_entry(log_entry)
                
                return JSONResponse(content={
                    "domain": domain,
                    "ip_address": ip_address,
                    "error": geo_data.get('message', 'Geolocation failed'),
                    "status": "geo_failed"
                }, status_code=400)
        else:
            log_entry = LogEntry(
                domain=domain,
                action="geolocation_check",
                status="error",
                details=f"Erreur API géolocalisation: {response.status_code}"
            )
            add_log_entry(log_entry)
            
            return JSONResponse(content={
                "domain": domain,
                "ip_address": ip_address,
                "error": f"Geolocation API error: {response.status_code}",
                "status": "api_error"
            }, status_code=response.status_code)
            
    except requests.exceptions.Timeout:
        log_entry = LogEntry(
            domain=domain,
            action="geolocation_check",
            status="warning",
            details="Timeout lors de la requête de géolocalisation"
        )
        add_log_entry(log_entry)
        
        return JSONResponse(content={
            "domain": domain,
            "error": "Request timeout",
            "status": "timeout"
        }, status_code=408)
        
    except Exception as e:
        log_entry = LogEntry(
            domain=domain,
            action="geolocation_check",
            status="error",
            details=f"Erreur lors de la géolocalisation: {str(e)}"
        )
        add_log_entry(log_entry)
        
        return JSONResponse(content={
             "domain": domain,
             "error": str(e),
             "status": "error"
         }, status_code=500)

# POST /bulk_classify
@app.post("/bulk_classify")
async def bulk_classify():
    conn = get_db_connection()
    cursor = conn.cursor(cursor_factory=DictCursor)
    
    try:
        # Récupérer les alertes à mettre à jour (statut 'new')
        cursor.execute('SELECT id, detected_domain FROM alerts WHERE status = %s', ('new',))
        alerts_to_update = cursor.fetchall()
        
        # Mettre à jour le statut des alertes
        for alert in alerts_to_update:
            cursor.execute('UPDATE alerts SET status = %s WHERE id = %s', ('pending', alert['id']))
            
            # Ajouter une entrée de log pour chaque alerte mise à jour
            log_entry = LogEntry(
                alert_id=alert['id'],
                domain=alert['detected_domain'],
                action="bulk_classify",
                status="information",
                details="Classification automatique initiée"
            )
            add_log_entry(log_entry)
        
        conn.commit()
        
        return JSONResponse({
            'success': True,
            'processed': len(alerts_to_update),
            'message': f'{len(alerts_to_update)} domaines mis en classification automatique'
        })
    
    except Exception as e:
        conn.rollback()
        
        # Ajouter une entrée de log pour l'erreur
        log_entry = LogEntry(
            domain="system",
            action="bulk_classify",
            status="error",
            details=f"Erreur lors de la classification en lot: {str(e)}"
        )
        add_log_entry(log_entry)
        
        return JSONResponse({
            'success': False,
            'error': str(e)
        }, status_code=500)
    
    finally:
        cursor.close()
        conn.close()
   
# GET /sync_database
@app.get("/sync_database")
async def sync_database():
    try:
        conn = get_db_connection()
        cursor = conn.cursor(cursor_factory=DictCursor)
        
        # Compter les nouvelles alertes (statut 'new')
        cursor.execute('SELECT COUNT(*) as count FROM alerts WHERE status = %s', ('new',))
        new_alerts = cursor.fetchone()['count']
        
        # Compter les alertes récentes (dans les dernières 24h)
        cursor.execute('''
            SELECT COUNT(*) as count FROM alerts 
            WHERE detection_date > NOW() - INTERVAL '24 hours'
        ''')
        updated_alerts = cursor.fetchone()['count']
        
        # Compter le total des alertes pour information
        cursor.execute('SELECT COUNT(*) as count FROM alerts')
        total_alerts = cursor.fetchone()['count']
        
        cursor.close()
        conn.close()
        
        # Ajouter une entrée de log pour la synchronisation
        log_entry = LogEntry(
            domain="system",
            action="sync_database",
            status="information",
            details=f"Synchronisation réussie: {new_alerts} nouvelles alertes, {updated_alerts} alertes récentes (24h), {total_alerts} alertes au total"
        )
        add_log_entry(log_entry)
        
        return JSONResponse({
            'success': True,
            'new_alerts': new_alerts,
            'recent_alerts': updated_alerts,
            'total_alerts': total_alerts,
            'timestamp': datetime.now().isoformat()
        })
    
    except Exception as e:
        # Ajouter une entrée de log pour l'erreur
        log_entry = LogEntry(
            domain="system",
            action="sync_database",
            status="error",
            details=f"Erreur lors de la synchronisation: {str(e)}"
        )
        add_log_entry(log_entry)
        
        return JSONResponse({
            'success': False,
            'error': str(e),
            'timestamp': datetime.now().isoformat()
        }, status_code=500)

@app.get("/risk_score")
async def calculate_risk_score(domain: str, original_domain: str = None):
    """Calcule le score de risque pour un domaine donné"""
    try:
        # Initialiser les données
        similarity_distance = None
        creation_date = None
        country_code = None
        ssl_status = None
        virustotal_detections = None
        
        # 1. Calculer la similarité si domaine original fourni
        if original_domain:
            similarity_distance = levenshtein_distance(domain, original_domain)
        
        # 2. Obtenir les données WHOIS (si activé)
        if is_feature_enabled('whois_api'):
            try:
                whois_data = whois.whois(domain)
                if whois_data and whois_data.creation_date:
                    creation_date = whois_data.creation_date
                    if isinstance(creation_date, list):
                        creation_date = creation_date[0]
            except Exception as e:
                print(f"Erreur WHOIS pour {domain}: {e}")
        else:
            print(f"API WHOIS désactivée pour {domain}")
        
        # 3. Obtenir la géolocalisation (si activé)
        if is_feature_enabled('geolocation_api'):
            try:
                # Résoudre l'IP du domaine
                ip = socket.gethostbyname(domain)
                
                # Obtenir la géolocalisation
                geo_response = requests.get(f"http://ip-api.com/json/{ip}", timeout=10)
                if geo_response.status_code == 200:
                    geo_data = geo_response.json()
                    if geo_data.get('status') == 'success':
                        country_code = geo_data.get('countryCode')
            except Exception as e:
                print(f"Erreur géolocalisation pour {domain}: {e}")
        else:
            print(f"API de géolocalisation désactivée pour {domain}")
        
        # 4. Vérifier le certificat SSL
        try:
            context = ssl.create_default_context()
            with socket.create_connection((domain, 443), timeout=10) as sock:
                with context.wrap_socket(sock, server_hostname=domain) as ssock:
                    cert = ssock.getpeercert()
                    if cert:
                        # Vérifier la validité du certificat
                        not_after = datetime.strptime(cert['notAfter'], '%b %d %H:%M:%S %Y %Z')
                        if not_after > datetime.now():
                            ssl_status = 'valid'
                        else:
                            ssl_status = 'expired'
                    else:
                        ssl_status = 'invalid'
        except Exception as e:
            ssl_status = 'none'
            print(f"Erreur SSL pour {domain}: {e}")
        
        # 5. Vérifier VirusTotal (si activé)
        if is_feature_enabled('virustotal_api'):
            vt_api_key = os.getenv('VIRUSTOTAL_API_KEY')
            if vt_api_key:
                try:
                    vt_url = f"https://www.virustotal.com/vtapi/v2/domain/report"
                    vt_params = {
                        'apikey': vt_api_key,
                        'domain': domain
                    }
                    vt_response = requests.get(vt_url, params=vt_params, timeout=10)
                    if vt_response.status_code == 200:
                        vt_data = vt_response.json()
                        if vt_data.get('response_code') == 1:
                            virustotal_detections = vt_data.get('positives', 0)
                except Exception as e:
                    print(f"Erreur VirusTotal pour {domain}: {e}")
        else:
            print(f"API VirusTotal désactivée pour {domain}")
        
        # Calculer le score global
        risk_analysis = calculate_overall_risk_score(
            similarity_distance=similarity_distance,
            creation_date=creation_date,
            country_code=country_code,
            ssl_status=ssl_status,
            virustotal_detections=virustotal_detections
        )
        
        # Ajouter les données brutes pour référence
        risk_analysis['raw_data'] = {
            'domain': domain,
            'original_domain': original_domain,
            'similarity_distance': similarity_distance,
            'creation_date': creation_date.isoformat() if isinstance(creation_date, datetime) else str(creation_date),
            'country_code': country_code,
            'ssl_status': ssl_status,
            'virustotal_detections': virustotal_detections
        }
        
        # Ajouter l'action recommandée
        risk_analysis['recommended_action'] = get_recommended_action(risk_analysis['overall_score'])
        
        # Log de l'analyse
        log_entry = LogEntry(
            domain=domain,
            action="risk_analysis",
            status="information",
            details=f"Score calculé: {risk_analysis['overall_score']}, Niveau: {risk_analysis['risk_level']}"
        )
        add_log_entry(log_entry)
        
        return JSONResponse(risk_analysis)
        
    except Exception as e:
        # Log de l'erreur
        log_entry = LogEntry(
            domain=domain,
            action="risk_analysis",
            status="error",
            details=f"Erreur lors du calcul: {str(e)}"
        )
        add_log_entry(log_entry)
        
        return JSONResponse({
            'error': str(e),
            'domain': domain
        }, status_code=500)

# POST /update_alert_score
@app.post("/update_alert_score")
async def update_alert_score(alert_id: int, domain: str = None, original_domain: str = None):
    """Met à jour le score de risque d'une alerte existante"""
    try:
        conn = get_db_connection()
        cursor = conn.cursor(cursor_factory=DictCursor)
        
        # Récupérer les informations de l'alerte
        cursor.execute("""
            SELECT a.*, wd.domain AS original_domain
            FROM alerts a
            JOIN watched_domains wd ON a.watched_domain_id = wd.id
            WHERE a.id = %s
        """, (alert_id,))
        
        alert = cursor.fetchone()
        if not alert:
            return JSONResponse({
                'success': False,
                'error': 'Alerte non trouvée'
            }, status_code=404)
        
        # Utiliser les domaines fournis ou ceux de l'alerte
        target_domain = domain or alert['detected_domain']
        source_domain = original_domain or alert['original_domain']
        
        # Calculer le nouveau score de risque
        risk_analysis = calculate_risk_score(target_domain, source_domain)
        
        if isinstance(risk_analysis, JSONResponse):
            risk_data = risk_analysis.body.decode('utf-8')
            risk_json = json.loads(risk_data)
            
            if 'error' not in risk_json:
                # Mettre à jour l'alerte avec les nouveaux scores
                cursor.execute("""
                    UPDATE alerts SET 
                        risk_score = %s,
                        similarity_score = %s,
                        domain_age_score = %s,
                        geolocation_score = %s,
                        ssl_score = %s,
                        reputation_score = %s,
                        risk_level = %s,
                        recommended_action = %s,
                        last_analysis = %s
                    WHERE id = %s
                """, (
                    risk_json['overall_score'],
                    risk_json['components']['similarity'],
                    risk_json['components']['domain_age'],
                    risk_json['components']['geolocation'],
                    risk_json['components']['ssl'],
                    risk_json['components']['reputation'],
                    risk_json['risk_level'],
                    risk_json['recommended_action'],
                    datetime.now(),
                    alert_id
                ))
                
                # Enregistrer l'historique du score
                cursor.execute("""
                    INSERT INTO risk_score_history 
                    (alert_id, overall_score, similarity_score, domain_age_score, 
                     geolocation_score, ssl_score, reputation_score, calculation_date)
                    VALUES (%s, %s, %s, %s, %s, %s, %s, %s)
                """, (
                    alert_id,
                    risk_json['overall_score'],
                    risk_json['components']['similarity'],
                    risk_json['components']['domain_age'],
                    risk_json['components']['geolocation'],
                    risk_json['components']['ssl'],
                    risk_json['components']['reputation'],
                    datetime.now()
                ))
                
                conn.commit()
                
                # Log de la mise à jour
                log_entry = LogEntry(
                    alert_id=alert_id,
                    domain=target_domain,
                    action="update_score",
                    status="information",
                    details=f"Score mis à jour: {risk_json['overall_score']}, Niveau: {risk_json['risk_level']}"
                )
                add_log_entry(log_entry)
                
                return JSONResponse({
                    'success': True,
                    'alert_id': alert_id,
                    'new_score': risk_json['overall_score'],
                    'risk_level': risk_json['risk_level'],
                    'components': risk_json['components'],
                    'recommended_action': risk_json['recommended_action']
                })
            else:
                return JSONResponse({
                    'success': False,
                    'error': f"Erreur lors du calcul du score: {risk_json.get('error', 'Erreur inconnue')}"
                }, status_code=500)
        
    except Exception as e:
        if 'conn' in locals():
            conn.rollback()
        
        # Log de l'erreur
        log_entry = LogEntry(
            alert_id=alert_id,
            domain=domain or "unknown",
            action="update_score",
            status="error",
            details=f"Erreur lors de la mise à jour du score: {str(e)}"
        )
        add_log_entry(log_entry)
        
        return JSONResponse({
            'success': False,
            'error': str(e)
        }, status_code=500)
    
    finally:
        if 'cursor' in locals():
            cursor.close()
        if 'conn' in locals():
            conn.close()

# ============================================================================
# ADMINISTRATION ENDPOINTS
# ============================================================================

# Modèles pour l'administration
class ScoringConfigUpdate(BaseModel):
    weights: dict
    thresholds: dict

class FeaturesConfigUpdate(BaseModel):
    features: dict

# Variable globale pour stocker la configuration des fonctionnalités
FEATURE_CONFIG = {
    'auto_monitoring': True,
    'auto_transitions': True,
    'auto_scoring': True,
    'email_notifications': True,
    'high_risk_alerts': True,
    'new_domain_alerts': True,
    'virustotal_api': True,
    'whois_api': True,
    'geolocation_api': True,
    'auto_cleanup': True,
    'auto_backup': False,
    'debug_mode': False
}

@app.get("/admin", response_class=HTMLResponse)
async def admin_page(request: Request):
    """Page d'administration"""
    return templates.TemplateResponse("admin.html", {"request": request})

@app.get("/admin/config")
async def get_admin_config():
    """Récupérer la configuration actuelle"""
    try:
        # Convertir les poids en pourcentages pour l'affichage
        weights_percent = {
            'similarity': int(SCORING_CONFIG['weights']['similarity'] * 100),
            'domain_age': int(SCORING_CONFIG['weights']['domain_age'] * 100),
            'geolocation': int(SCORING_CONFIG['weights']['geolocation'] * 100),
            'ssl_cert': int(SCORING_CONFIG['weights']['ssl_cert'] * 100),
            'reputation': int(SCORING_CONFIG['weights']['reputation'] * 100)
        }
        
        return JSONResponse({
            'weights': weights_percent,
            'thresholds': SCORING_CONFIG['thresholds'],
            'features': FEATURE_CONFIG
        })
    except Exception as e:
        return JSONResponse({
            'error': f'Erreur lors de la récupération de la configuration: {str(e)}'
        }, status_code=500)

@app.post("/admin/config/scoring")
async def update_scoring_config(config: ScoringConfigUpdate):
    """Mettre à jour la configuration de scoring"""
    try:
        # Valider que les poids totalisent 100%
        total_weight = sum(config.weights.values())
        if abs(total_weight - 1.0) > 0.01:
            return JSONResponse({
                'error': 'Le total des poids doit égaler 100%'
            }, status_code=400)
        
        # Mettre à jour la configuration globale
        SCORING_CONFIG['weights'].update(config.weights)
        SCORING_CONFIG['thresholds'].update(config.thresholds)
        
        # Log de la modification
        log_entry = LogEntry(
            domain="system",
            action="update_scoring_config",
            status="information",
            details=f"Configuration de scoring mise à jour - Poids: {config.weights}, Seuils: {config.thresholds}"
        )
        add_log_entry(log_entry)
        
        return JSONResponse({
            'success': True,
            'message': 'Configuration de scoring mise à jour avec succès'
        })
        
    except Exception as e:
        log_entry = LogEntry(
            domain="system",
            action="update_scoring_config",
            status="error",
            details=f"Erreur lors de la mise à jour de la configuration: {str(e)}"
        )
        add_log_entry(log_entry)
        
        return JSONResponse({
            'error': f'Erreur lors de la mise à jour: {str(e)}'
        }, status_code=500)

@app.post("/admin/config/features")
async def update_features_config(config: FeaturesConfigUpdate):
    """Mettre à jour la configuration des fonctionnalités"""
    try:
        # Mettre à jour la configuration globale
        FEATURE_CONFIG.update(config.features)
        
        # Log de la modification
        log_entry = LogEntry(
            domain="system",
            action="update_features_config",
            status="information",
            details=f"Configuration des fonctionnalités mise à jour: {config.features}"
        )
        add_log_entry(log_entry)
        
        return JSONResponse({
            'success': True,
            'message': 'Configuration des fonctionnalités mise à jour avec succès'
        })
        
    except Exception as e:
        log_entry = LogEntry(
            domain="system",
            action="update_features_config",
            status="error",
            details=f"Erreur lors de la mise à jour des fonctionnalités: {str(e)}"
        )
        add_log_entry(log_entry)
        
        return JSONResponse({
            'error': f'Erreur lors de la mise à jour: {str(e)}'
        }, status_code=500)

@app.post("/admin/actions/recalculate-scores")
async def recalculate_all_scores():
    """Recalculer tous les scores de risque"""
    try:
        conn = get_db_connection()
        cursor = conn.cursor(cursor_factory=DictCursor)
        
        # Récupérer toutes les alertes actives
        cursor.execute("""
            SELECT id, detected_domain, original_domain, lev_distance, 
                   whois_created, dns_a, issuer, status
            FROM alerts 
            WHERE status IN ('new', 'investigating', 'monitoring')
        """)
# 
        alerts = cursor.fetchall()
        updated_count = 0
        
        for alert in alerts:
            try:
                # Recalculer le score avec les données disponibles
                risk_data = calculate_overall_risk_score(
                    similarity_distance=alert['lev_distance'],
                    creation_date=alert['whois_created'],
                    country_code=None,  # Pas disponible dans la table
                    ssl_status=alert['issuer'] is not None,  # Utiliser l'issuer SSL comme indicateur
                    virustotal_detections=None  # Pas disponible dans la table
                )
                
                if risk_data['success']:
                    # Mettre à jour en base
                    cursor.execute("""
                        UPDATE alerts SET 
                            risk_score = %s,
                            similarity_score = %s,
                            domain_age_score = %s,
                            geolocation_score = %s,
                            ssl_score = %s,
                            reputation_score = %s,
                            risk_level = %s,
                            recommended_action = %s,
                            last_analysis = %s
                        WHERE id = %s
                    """, (
                        risk_data['overall_score'],
                        risk_data['components']['similarity'],
                        risk_data['components']['domain_age'],
                        risk_data['components']['geolocation'],
                        risk_data['components']['ssl'],
                        risk_data['components']['reputation'],
                        risk_data['risk_level'],
                        risk_data['recommended_action'],
                        datetime.now(),
                        alert['id']
                    ))
                    updated_count += 1
                    
            except Exception as e:
                print(f"Erreur lors du recalcul pour l'alerte {alert['id']}: {str(e)}")
                continue
        
        conn.commit()
        
        # Log de l'opération
        log_entry = LogEntry(
            domain="system",
            action="recalculate_all_scores",
            status="information",
            details=f"Recalcul terminé - {updated_count} alertes mises à jour sur {len(alerts)}"
        )
        add_log_entry(log_entry)
        
        return JSONResponse({
            'success': True,
            'updated_count': updated_count,
            'total_alerts': len(alerts)
        })
        
    except Exception as e:
        if 'conn' in locals():
            conn.rollback()
            
        log_entry = LogEntry(
            domain="system",
            action="recalculate_all_scores",
            status="error",
            details=f"Erreur lors du recalcul des scores: {str(e)}"
        )
        add_log_entry(log_entry)
        
        return JSONResponse({
            'error': f'Erreur lors du recalcul: {str(e)}'
        }, status_code=500)
        
    finally:
        if 'cursor' in locals():
            cursor.close()
        if 'conn' in locals():
            conn.close()

@app.post("/admin/actions/cleanup-logs")
async def cleanup_old_logs():
    """Nettoyer les anciens logs"""
    try:
        # Charger les logs existants
        logs = get_logs(limit=10000)  # Récupérer tous les logs
        
        # Filtrer les logs de plus de 30 jours
        cutoff_date = datetime.now() - timedelta(days=30)
        recent_logs = []
        deleted_count = 0
        
        for log in logs:
            log_date = datetime.fromisoformat(log['timestamp'].replace('Z', '+00:00'))
            if log_date >= cutoff_date:
                recent_logs.append(log)
            else:
                deleted_count += 1
        
        # Sauvegarder les logs récents
        with open(LOGS_FILE, 'w', encoding='utf-8') as f:
            json.dump(recent_logs, f, ensure_ascii=False, indent=2, default=str)
        
        # Log de l'opération
        log_entry = LogEntry(
            domain="system",
            action="cleanup_logs",
            status="information",
            details=f"Nettoyage des logs terminé - {deleted_count} logs supprimés"
        )
        add_log_entry(log_entry)
        
        return JSONResponse({
            'success': True,
            'deleted_count': deleted_count,
            'remaining_count': len(recent_logs)
        })
        
    except Exception as e:
        log_entry = LogEntry(
            domain="system",
            action="cleanup_logs",
            status="error",
            details=f"Erreur lors du nettoyage des logs: {str(e)}"
        )
        add_log_entry(log_entry)
        
        return JSONResponse({
            'error': f'Erreur lors du nettoyage: {str(e)}'
        }, status_code=500)

@app.get("/admin/health")
async def system_health_check():
    """Vérifier la santé du système"""
    try:
        health_status = {
            'status': 'healthy',
            'checks': {},
            'issues': []
        }
        
        # Test de connexion à la base de données
        try:
            conn = get_db_connection()
            cursor = conn.cursor()
            cursor.execute("SELECT 1")
            cursor.fetchone()
            health_status['checks']['database'] = 'ok'
            cursor.close()
            conn.close()
        except Exception as e:
            health_status['checks']['database'] = 'error'
            health_status['issues'].append(f'Base de données: {str(e)}')
        
        # Vérifier l'espace disque pour les logs
        try:
            import shutil
            disk_usage = shutil.disk_usage('.')
            free_space_gb = disk_usage.free / (1024**3)
            if free_space_gb < 1:  # Moins de 1 GB libre
                health_status['checks']['disk_space'] = 'warning'
                health_status['issues'].append(f'Espace disque faible: {free_space_gb:.1f} GB')
            else:
                health_status['checks']['disk_space'] = 'ok'
        except Exception as e:
            health_status['checks']['disk_space'] = 'error'
            health_status['issues'].append(f'Vérification espace disque: {str(e)}')
        
        # Vérifier la taille du fichier de logs
        try:
            if os.path.exists(LOGS_FILE):
                log_size_mb = os.path.getsize(LOGS_FILE) / (1024**2)
                if log_size_mb > 100:  # Plus de 100 MB
                    health_status['checks']['log_size'] = 'warning'
                    health_status['issues'].append(f'Fichier de logs volumineux: {log_size_mb:.1f} MB')
                else:
                    health_status['checks']['log_size'] = 'ok'
            else:
                health_status['checks']['log_size'] = 'ok'
        except Exception as e:
            health_status['checks']['log_size'] = 'error'
            health_status['issues'].append(f'Vérification logs: {str(e)}')
        
        # Déterminer le statut global
        if health_status['issues']:
            if any('error' in check for check in health_status['checks'].values()):
                health_status['status'] = 'unhealthy'
            else:
                health_status['status'] = 'degraded'
        
        return JSONResponse(health_status)
        
    except Exception as e:
        return JSONResponse({
            'status': 'unhealthy',
            'error': f'Erreur lors de la vérification: {str(e)}'
        }, status_code=500)

# Fonction utilitaire pour vérifier si une fonctionnalité est activée
def is_feature_enabled(feature_name: str) -> bool:
    """Vérifier si une fonctionnalité est activée"""
    return FEATURE_CONFIG.get(feature_name, False)

# Configuration par défaut pour l'administration
DEFAULT_CONFIG = {
    'weights': {
        'similarity': 0.40,
        'domain_age': 0.25,
        'geolocation': 0.15,
        'ssl_cert': 0.10,
        'reputation': 0.10
    },
    'thresholds': {
        'low_risk': 30,
        'medium_risk': 70
    },
    'features': {
        'auto_monitoring': True,
        'auto_transitions': True,
        'auto_scoring': True,
        'email_notifications': True,
        'high_risk_alerts': True,
        'new_domain_alerts': True,
        'virustotal_api': True,
        'whois_api': True,
        'geolocation_api': True,
        'auto_cleanup': True,
        'auto_backup': False,
        'debug_mode': False
    }
}

# Variable globale pour stocker la configuration
current_admin_config = DEFAULT_CONFIG.copy()

# Endpoints d'administration
@app.get("/admin/config")
async def get_admin_config():
    """Récupérer la configuration actuelle"""
    return JSONResponse(current_admin_config)

@app.post("/admin/config/scoring")
async def save_scoring_config(config: ScoringConfig):
    """Sauvegarder la configuration de scoring"""
    try:
        global current_admin_config
        
        # Valider que les poids totalisent 100%
        total_weight = sum(config.weights.values())
        if abs(total_weight - 1.0) > 0.01:
            return JSONResponse({
                'error': 'Le total des poids doit égaler 100%'
            }, status_code=400)
        
        # Mettre à jour la configuration
        current_admin_config['weights'] = config.weights
        current_admin_config['thresholds'] = config.thresholds
        
        # Log de l'opération
        log_entry = LogEntry(
            domain="system",
            action="update_scoring_config",
            status="information",
            details="Configuration de scoring mise à jour"
        )
        add_log_entry(log_entry)
        
        return JSONResponse({
            'success': True,
            'message': 'Configuration de scoring sauvegardée avec succès'
        })
        
    except Exception as e:
        log_entry = LogEntry(
            domain="system",
            action="update_scoring_config",
            status="error",
            details=f"Erreur lors de la mise à jour: {str(e)}"
        )
        add_log_entry(log_entry)
        
        return JSONResponse({
            'error': f'Erreur lors de la sauvegarde: {str(e)}'
        }, status_code=500)

@app.post("/admin/config/features")
async def save_features_config(config: FeaturesConfig):
    """Sauvegarder la configuration des fonctionnalités"""
    try:
        global current_admin_config
        
        # Mettre à jour la configuration
        current_admin_config['features'] = config.features
        
        # Log de l'opération
        log_entry = LogEntry(
            domain="system",
            action="update_features_config",
            status="information",
            details="Configuration des fonctionnalités mise à jour"
        )
        add_log_entry(log_entry)
        
        return JSONResponse({
            'success': True,
            'message': 'Configuration des fonctionnalités sauvegardée avec succès'
        })
        
    except Exception as e:
        log_entry = LogEntry(
            domain="system",
            action="update_features_config",
            status="error",
            details=f"Erreur lors de la mise à jour: {str(e)}"
        )
        add_log_entry(log_entry)
        
        return JSONResponse({
            'error': f'Erreur lors de la sauvegarde: {str(e)}'
        }, status_code=500)

@app.post("/admin/actions/recalculate-scores")
async def recalculate_all_scores():
    """Recalculer tous les scores des alertes"""
    try:
        conn = get_db_connection()
        cursor = conn.cursor(cursor_factory=DictCursor)
        
        # Récupérer toutes les alertes
        cursor.execute('SELECT * FROM alerts WHERE status != %s', ('archived',))
        alerts = cursor.fetchall()
        
        updated_count = 0
        
        for alert in alerts:
            # Recalculer le score avec la configuration actuelle
            new_score = calculate_overall_risk_score(
                similarity_distance=alert.get('levenshtein_distance'),
                creation_date=alert.get('creation_date'),
                country_code=alert.get('country_code'),
                ssl_status=alert.get('ssl_status'),
                virustotal_detections=alert.get('virustotal_detections')
            )
            
            # Mettre à jour le score dans la base de données
            cursor.execute(
                'UPDATE alerts SET risk_score = %s WHERE id = %s',
                (new_score['overall_score'], alert['id'])
            )
            updated_count += 1
        
        conn.commit()
        cursor.close()
        conn.close()
        
        # Log de l'opération
        log_entry = LogEntry(
            domain="system",
            action="recalculate_scores",
            status="information",
            details=f"Scores recalculés pour {updated_count} alertes"
        )
        add_log_entry(log_entry)
        
        return JSONResponse({
            'success': True,
            'updated_count': updated_count,
            'message': f'Scores recalculés pour {updated_count} alertes'
        })
        
    except Exception as e:
        log_entry = LogEntry(
            domain="system",
            action="recalculate_scores",
            status="error",
            details=f"Erreur lors du recalcul: {str(e)}"
        )
        add_log_entry(log_entry)
        
        return JSONResponse({
            'error': f'Erreur lors du recalcul: {str(e)}'
        }, status_code=500)
