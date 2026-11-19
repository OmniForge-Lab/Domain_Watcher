from fastapi import APIRouter, Request, Depends
from fastapi.responses import JSONResponse
import socket
import whois
import logging

router = APIRouter()

def get_db_connection():
    """Importe la fonction depuis le module principal"""
    from main import get_db_connection
    return get_db_connection()

@router.get("/update_domain_info")
async def update_domain_info(request: Request):
    """Met à jour les informations DNS et WHOIS pour les alertes"""
    alert_id = request.query_params.get('alert_id')
    
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        
        # Si un ID d'alerte est fourni, mettre à jour uniquement cette alerte
        if alert_id:
            cursor.execute("SELECT detected_domain FROM alerts WHERE id = %s", (alert_id,))
            result = cursor.fetchone()
            if not result:
                return JSONResponse({"error": "Alerte non trouvée"}, status_code=404)
                
            domain = result[0]
            updated = update_single_domain_info(conn, cursor, alert_id, domain)
            
            if updated:
                return JSONResponse({"message": f"Informations mises à jour pour {domain}"})
            else:
                return JSONResponse({"error": "Impossible de mettre à jour les informations"}, status_code=500)
        
        # Sinon, mettre à jour les 50 alertes les plus récentes sans informations
        else:
            cursor.execute("""
                SELECT id, detected_domain FROM alerts 
                WHERE (dns_a IS NULL OR dns_a = '' OR whois_registrar IS NULL OR whois_registrar = '')
                ORDER BY id DESC LIMIT 50
            """)
            alerts = cursor.fetchall()
            
            if not alerts:
                return JSONResponse({"message": "Aucune alerte nécessitant une mise à jour trouvée"})
                
            updated_count = 0
            for alert in alerts:
                alert_id, domain = alert
                if update_single_domain_info(conn, cursor, alert_id, domain):
                    updated_count += 1
            
            return JSONResponse({"message": f"{updated_count} alertes mises à jour sur {len(alerts)}"})
            
    except Exception as e:
        logging.error(f"Erreur lors de la mise à jour des informations: {str(e)}")
        return JSONResponse({"error": str(e)}, status_code=500)
    finally:
        if conn:
            conn.close()

def update_single_domain_info(conn, cursor, alert_id, domain):
    """Met à jour les informations DNS et WHOIS pour une seule alerte"""
    try:
        # Récupérer l'IP via DNS
        dns_a = None
        try:
            dns_a = socket.gethostbyname(domain)
        except Exception as e:
            logging.warning(f"Impossible de résoudre l'IP pour {domain}: {str(e)}")
        
        # Récupérer les informations WHOIS
        whois_registrar = None
        whois_created = None
        
        try:
            # Utiliser la bibliothèque whois pour obtenir les informations
            w = whois.whois(domain)
            if w.registrar:
                whois_registrar = w.registrar
            if w.creation_date:
                if isinstance(w.creation_date, list):
                    whois_created = str(w.creation_date[0])
                else:
                    whois_created = str(w.creation_date)
        except Exception as e:
            logging.warning(f"Erreur WHOIS pour {domain}: {str(e)}")
        
        # Mettre à jour la base de données
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
            
        if update_fields:
            params.append(alert_id)
            query = f"UPDATE alerts SET {', '.join(update_fields)} WHERE id = %s"
            cursor.execute(query, params)
            conn.commit()
            return True
            
        return False
    except Exception as e:
        logging.error(f"Erreur lors de la mise à jour de {domain}: {str(e)}")
        conn.rollback()
        return False