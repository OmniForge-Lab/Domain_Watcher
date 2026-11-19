#!/bin/bash
# Tâches de maintenance du système de typosquatting
# À exécuter quotidiennement

set -e

# Répertoire de l'application
cd "/home/toto/V2_App_Typo"

# Activer l'environnement virtuel si il existe
if [[ -f "venv/bin/activate" ]]; then
    source venv/bin/activate
fi

# Log de début
echo "[$(date '+%Y-%m-%d %H:%M:%S')] Début de la maintenance" >> maintenance_last_run.log

# Exécuter les tâches de maintenance
if python3 maintenance_tasks.py --tasks transitions scoring cleanup report notification >> maintenance_last_run.log 2>&1; then
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] Maintenance terminée avec succès" >> maintenance_last_run.log
else
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] Erreur lors de la maintenance" >> maintenance_last_run.log
    exit 1
fi
