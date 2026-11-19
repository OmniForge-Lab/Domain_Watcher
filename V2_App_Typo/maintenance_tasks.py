#!/usr/bin/env python3
"""
Tâches de maintenance automatisées pour le système de détection de typosquatting

Ce script doit être exécuté périodiquement (via cron ou tâche planifiée) pour :
- Effectuer les transitions automatiques d'état
- Recalculer les scores de risque
- Nettoyer les anciennes données
- Générer des rapports de synthèse
- Envoyer des notifications
"""

import os
import sys
import logging
import psycopg2
from psycopg2.extras import DictCursor
from datetime import datetime, timedelta
import requests
import json
import smtplib
#from email.mime.text import MimeText
#from email.mime.multipart import MimeMultipart
from dotenv import load_dotenv

# Charger les variables d'environnement
load_dotenv()

# Configuration du logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('maintenance.log'),
        logging.StreamHandler(sys.stdout)
    ]
)
logger = logging.getLogger(__name__)

# Configuration de la base de données
DB_CONFIG = {
    'host': os.getenv('DB_HOST'),
    'database': os.getenv('DB_NAME'),
    'user': os.getenv('DB_USER'),
    'password': os.getenv('DB_PASS')
}

# Configuration email
EMAIL_CONFIG = {
    'smtp_server': os.getenv('SMTP_SERVER', 'localhost'),
    'smtp_port': int(os.getenv('SMTP_PORT', '587')),
    'smtp_user': os.getenv('SMTP_USER'),
    'smtp_password': os.getenv('SMTP_PASSWORD'),
    'from_email': os.getenv('FROM_EMAIL', 'typosquatting@company.com'),
    'to_emails': os.getenv('TO_EMAILS', '').split(',') if os.getenv('TO_EMAILS') else []
}

class MaintenanceManager:
    def __init__(self):
        self.conn = None
        self.cursor = None
        
    def connect_db(self):
        """Établir la connexion à la base de données"""
        try:
            self.conn = psycopg2.connect(**DB_CONFIG)
            self.cursor = self.conn.cursor(cursor_factory=DictCursor)
            logger.info("Connexion à la base de données établie")
        except Exception as e:
            logger.error(f"Erreur de connexion à la base de données: {e}")
            raise
    
    def disconnect_db(self):
        """Fermer la connexion à la base de données"""
        if self.cursor:
            self.cursor.close()
        if self.conn:
            self.conn.close()
        logger.info("Connexion à la base de données fermée")
    
    def auto_transition_alerts(self):
        """Effectuer les transitions automatiques d'état"""
        logger.info("Début des transitions automatiques d'état")
        
        try:
            # Appeler la fonction PostgreSQL pour les transitions automatiques
            self.cursor.execute("SELECT auto_transition_alerts()")
            transition_count = self.cursor.fetchone()[0]
            self.conn.commit()
            
            logger.info(f"Transitions automatiques effectuées: {transition_count}")
            return transition_count
            
        except Exception as e:
            logger.error(f"Erreur lors des transitions automatiques: {e}")
            self.conn.rollback()
            return 0
    
    def recalculate_risk_scores(self, max_alerts=500):
        """Recalculer les scores de risque pour les alertes anciennes"""
        logger.info(f"Début du recalcul des scores de risque (max {max_alerts} alertes)")
        
        try:
            # Sélectionner les alertes à recalculer
            self.cursor.execute("""
                SELECT a.id, a.detected_domain, wd.domain as original_domain
                FROM alerts a
                JOIN watched_domains wd ON a.watched_domain_id = wd.id
                WHERE (a.last_analysis IS NULL OR a.last_analysis < NOW() - INTERVAL '7 days')
                AND a.status NOT IN ('resolved', 'false_positive', 'blocked')
                ORDER BY 
                    CASE WHEN a.last_analysis IS NULL THEN 0 ELSE 1 END,
                    a.detection_date DESC
                LIMIT %s;
            """, (max_alerts,))
            
            alerts_to_update = self.cursor.fetchall()
            updated_count = 0
            
            for alert in alerts_to_update:
                try:
                    # Appeler l'API de calcul de score
                    response = requests.get(
                        f"http://localhost:8000/risk_score",
                        params={
                            'domain': alert['detected_domain'],
                            'original_domain': alert['original_domain']
                        },
                        #timeout=30
                    )
                    
                    if response.status_code == 200:
                        risk_data = response.json()
                        score = risk_data['overall_score']
                        risk_level = risk_data['risk_level']
                        
                        # Mettre à jour la base de données
                        self.cursor.execute("""
                            UPDATE alerts 
                            SET risk_score = %s, 
                                risk_level = %s,
                                last_analysis = %s,
                                similarity_score = %s,
                                domain_age_score = %s,
                                geolocation_score = %s,
                                ssl_score = %s,
                                reputation_score = %s,
                                recommended_action = %s
                            WHERE id = %s;
                        """, (
                            score,
                            risk_level,
                            datetime.now(),
                            risk_data['components']['similarity'],
                            risk_data['components']['domain_age'],
                            risk_data['components']['geolocation'],
                            risk_data['components']['ssl'],
                            risk_data['components']['reputation'],
                            risk_data['recommended_action'],
                            alert['id']
                        ))
                        
                        # Enregistrer l'historique
                        self.cursor.execute("""
                            INSERT INTO risk_score_history 
                            (alert_id, risk_score, similarity_score, domain_age_score, 
                             geolocation_score, ssl_score, reputation_score, risk_level)
                            VALUES (%s, %s, %s, %s, %s, %s, %s, %s);
                        """, (
                            alert['id'],
                            score,
                            risk_data['components']['similarity'],
                            risk_data['components']['domain_age'],
                            risk_data['components']['geolocation'],
                            risk_data['components']['ssl'],
                            risk_data['components']['reputation'],
                            risk_level
                        ))
                        
                        updated_count += 1
                        logger.info(f"Score mis à jour pour {alert['detected_domain']}: {score:.2f}")
                        
                    else:
                        logger.warning(f"Échec du calcul de score pour {alert['detected_domain']}: {response.status_code}")
                        
                except Exception as e:
                    logger.error(f"Erreur lors du calcul de score pour {alert['detected_domain']}: {e}")
                    continue
            
            self.conn.commit()
            logger.info(f"Scores recalculés pour {updated_count} alertes")
            return updated_count
            
        except Exception as e:
            logger.error(f"Erreur lors du recalcul des scores: {e}")
            self.conn.rollback()
            return 0
    
    def cleanup_old_data(self):
        """Nettoyer les anciennes données"""
        logger.info("Début du nettoyage des anciennes données")
        
        try:
            # Appeler la fonction PostgreSQL de nettoyage
            self.cursor.execute("SELECT cleanup_old_data()")
            cleanup_count = self.cursor.fetchone()[0]
            self.conn.commit()
            
            logger.info(f"Données nettoyées: {cleanup_count} enregistrements supprimés")
            return cleanup_count
            
        except Exception as e:
            logger.error(f"Erreur lors du nettoyage: {e}")
            self.conn.rollback()
            return 0
    
    def generate_daily_report(self):
        """Générer un rapport quotidien"""
        logger.info("Génération du rapport quotidien")
        
        try:
            # Statistiques générales
            self.cursor.execute("""
                SELECT 
                    COUNT(*) as total_alerts,
                    COUNT(CASE WHEN status = 'nouveau' THEN 1 END) as new_alerts,
                    COUNT(CASE WHEN status = 'action_required' THEN 1 END) as action_required,
                    COUNT(CASE WHEN status = 'escalated' THEN 1 END) as escalated,
                    COUNT(CASE WHEN risk_score >= 70 THEN 1 END) as high_risk,
                    COUNT(CASE WHEN detection_date::date = CURRENT_DATE THEN 1 END) as today_detections,
                    AVG(risk_score) as avg_risk_score
                FROM alerts
                WHERE status NOT IN ('resolved', 'false_positive', 'blocked');
            """)
            
            stats = self.cursor.fetchone()
            
            # Alertes nécessitant une attention
            self.cursor.execute("""
                SELECT detected_domain, risk_score, status, detection_date
                FROM alerts
                WHERE status IN ('action_required', 'escalated') 
                   OR (risk_score >= 70 AND status NOT IN ('resolved', 'false_positive', 'blocked'))
                ORDER BY risk_score DESC, detection_date DESC
                LIMIT 10;
            """)
            
            urgent_alerts = self.cursor.fetchall()
            
            # Domaines détectés aujourd'hui
            self.cursor.execute("""
                SELECT a.detected_domain, wd.domain as original_domain, a.risk_score, a.status
                FROM alerts a
                JOIN watched_domains wd ON a.watched_domain_id = wd.id
                WHERE a.detection_date::date = CURRENT_DATE
                ORDER BY a.risk_score DESC;
            """)
            
            today_alerts = self.cursor.fetchall()
            
            report = {
                'date': datetime.now().strftime('%Y-%m-%d'),
                'statistics': dict(stats),
                'urgent_alerts': [dict(alert) for alert in urgent_alerts],
                'today_alerts': [dict(alert) for alert in today_alerts]
            }
            
            # Sauvegarder le rapport
            report_file = f"reports/daily_report_{datetime.now().strftime('%Y%m%d')}.json"
            os.makedirs('reports', exist_ok=True)
            
            with open(report_file, 'w', encoding='utf-8') as f:
                json.dump(report, f, ensure_ascii=False, indent=2, default=str)
            
            logger.info(f"Rapport quotidien généré: {report_file}")
            return report
            
        except Exception as e:
            logger.error(f"Erreur lors de la génération du rapport: {e}")
            return None
    
    #def send_notification_email(self, report):
    #    """Envoyer un email de notification avec le rapport"""
    #    if not EMAIL_CONFIG['to_emails'] or not EMAIL_CONFIG['smtp_user']:
    #        logger.info("Configuration email manquante, notification ignorée")
    #        return False
    #    
    #    try:
    #        stats = report['statistics']
    #        urgent_count = len(report['urgent_alerts'])
    #        today_count = len(report['today_alerts'])
    #        
    #        # Créer le message
    #        msg = MimeMultipart()
    #        msg['From'] = EMAIL_CONFIG['from_email']
    #        msg['To'] = ', '.join(EMAIL_CONFIG['to_emails'])
    #        msg['Subject'] = f"Rapport Typosquatting - {report['date']}"
    #        
    #        # Corps du message
    #        body = f"""
    #        Rapport quotidien du système de détection de typosquatting
    #        Date: {report['date']}
    #        
    #        STATISTIQUES GÉNÉRALES:
    #        - Total des alertes actives: {stats['total_alerts']}
    #        - Nouvelles alertes: {stats['new_alerts']}
    #        - Actions requises: {stats['action_required']}
    #        - Alertes escaladées: {stats['escalated']}
    #        - Alertes haut risque: {stats['high_risk']}
    #        - Détections aujourd'hui: {stats['today_detections']}
    #        - Score de risque moyen: {stats['avg_risk_score']:.2f}
    #        
    #        ALERTES URGENTES ({urgent_count}):
    #        """
    #        
    #        for alert in report['urgent_alerts'][:5]:  # Top 5
    #            body += f"\n- {alert['detected_domain']} (Score: {alert['risk_score']:.1f}, Statut: {alert['status']})"
    #        
    #        if urgent_count > 5:
    #            body += f"\n... et {urgent_count - 5} autres"
    #        
    #        body += f"""
    #        
    #        NOUVELLES DÉTECTIONS AUJOURD'HUI ({today_count}):
    #        """
    #        
    #        for alert in report['today_alerts'][:5]:  # Top 5
    #            body += f"\n- {alert['detected_domain']} -> {alert['original_domain']} (Score: {alert['risk_score']:.1f})"
    #        
    #        if today_count > 5:
    #            body += f"\n... et {today_count - 5} autres"
    #        
    #        body += """
    #        
    #        Accéder au système: http://localhost:8000
    #        
    #        Ce rapport est généré automatiquement.
    #        """
    #        
    #        msg.attach(MimeText(body, 'plain', 'utf-8'))
    #        
    #        # Envoyer l'email
    #        server = smtplib.SMTP(EMAIL_CONFIG['smtp_server'], EMAIL_CONFIG['smtp_port'])
    #        server.starttls()
    #        server.login(EMAIL_CONFIG['smtp_user'], EMAIL_CONFIG['smtp_password'])
    #        server.send_message(msg)
    #        server.quit()
    #        
    #        logger.info(f"Email de notification envoyé à {len(EMAIL_CONFIG['to_emails'])} destinataires")
    #        return True
    #        
    #    except Exception as e:
    #        logger.error(f"Erreur lors de l'envoi de l'email: {e}")
    #        return False
    
    def run_maintenance(self, tasks=None):
        """Exécuter les tâches de maintenance"""
        if tasks is None:
            tasks = ['transitions', 'scoring', 'cleanup', 'report']
        
        logger.info(f"Début de la maintenance - Tâches: {', '.join(tasks)}")
        
        try:
            self.connect_db()
            results = {}
            
            if 'transitions' in tasks:
                results['transitions'] = self.auto_transition_alerts()
            
            if 'scoring' in tasks:
                results['scoring'] = self.recalculate_risk_scores()
            
            if 'cleanup' in tasks:
                results['cleanup'] = self.cleanup_old_data()
            
            if 'report' in tasks:
                report = self.generate_daily_report()
                results['report'] = report is not None
                
                if report and 'notification' in tasks:
                    results['notification'] = self.send_notification_email(report)
            
            logger.info(f"Maintenance terminée - Résultats: {results}")
            return results
            
        except Exception as e:
            logger.error(f"Erreur lors de la maintenance: {e}")
            return {'error': str(e)}
        
        finally:
            self.disconnect_db()

def main():
    """Point d'entrée principal"""
    import argparse
    
    parser = argparse.ArgumentParser(description='Tâches de maintenance du système de typosquatting')
    parser.add_argument('--tasks', nargs='+', 
                       choices=['transitions', 'scoring', 'cleanup', 'report', 'notification'],
                       default=['transitions', 'scoring', 'cleanup', 'report'],
                       help='Tâches à exécuter')
    parser.add_argument('--max-alerts', type=int, default=50,
                       help='Nombre maximum d\'alertes à recalculer')
    parser.add_argument('--verbose', '-v', action='store_true',
                       help='Mode verbeux')
    
    args = parser.parse_args()
    
    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)
    
    manager = MaintenanceManager()
    results = manager.run_maintenance(args.tasks)
    
    if 'error' in results:
        sys.exit(1)
    else:
        sys.exit(0)

if __name__ == '__main__':
    main()
