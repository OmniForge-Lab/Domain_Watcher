# 🚀 GUIDE DE DÉPLOIEMENT RAPIDE

## 📋 Résumé

Ce guide vous permet de déployer rapidement toutes les améliorations du système de typosquatting, quel que soit votre environnement (Windows ou Linux).

## ⚡ Déploiement automatique

### 1. Exécuter le script de déploiement

```bash
# Le script détecte automatiquement votre OS
python deploy_improvements.py
```

### 2. Configurer les tâches planifiées

#### 🪟 Sur Windows
```powershell
# En tant qu'administrateur
.\setup_scheduled_tasks.ps1
```

#### 🐧 Sur Linux
```bash
# Rendre le script exécutable
chmod +x setup_scheduled_tasks.sh

# Exécuter la configuration
./setup_scheduled_tasks.sh
```

## 🔧 Vérification du déploiement

### Tester la configuration

#### Windows
```powershell
# Tester les tâches
.\setup_scheduled_tasks.ps1 -Test

# Voir les tâches planifiées
Get-ScheduledTask -TaskName '*Typosquatting*'
```

#### Linux
```bash
# Tester les tâches
./setup_scheduled_tasks.sh --test

# Voir les tâches cron
crontab -l | grep typosquatting
```

### Vérifier l'application

```bash
# Démarrer l'application
python main.py

# Tester le nouveau endpoint de scoring
curl "http://localhost:8000/risk_score?domain=test.com&original_domain=example.com"
```

## 📊 Nouveautés déployées

### ✅ Système de scoring automatisé
- **5 composants** : Similarité (40%), Âge (20%), Géolocalisation (15%), SSL (15%), Réputation (10%)
- **3 niveaux** : Faible (0-30), Modéré (30-70), Élevé (70-100)
- **Actions automatiques** selon le score

### ✅ Nouveaux états d'alerte
- **Actifs** : `nouveau`, `investigating`, `monitoring`
- **Intervention** : `action_required`, `escalated`
- **Passifs** : `legitimate`, `parked`, `expired`
- **Finaux** : `resolved`, `false_positive`, `blocked`

### ✅ Automatisation complète
- **Quotidienne (02:00)** : Transitions, scoring, nettoyage, rapports
- **Horaire** : Surveillance des transitions
- **Temps réel** : Calcul de scores via API

### ✅ Base de données enrichie
- Nouvelles tables pour historique et configuration
- Colonnes de scoring dans la table `alerts`
- Vues et fonctions PostgreSQL

## 🎯 Utilisation immédiate

### Interface utilisateur
1. **Accéder à l'application** : `http://localhost:8000`
2. **Voir les nouveaux scores** dans la liste des alertes
3. **Utiliser les nouveaux filtres** par niveau de risque
4. **Consulter l'historique** des changements d'état

### API
```bash
# Calculer le score d'un domaine
GET /risk_score?domain=suspicious.com&original_domain=legitimate.com

# Mettre à jour le score d'une alerte
POST /update_alert_score
{
  "alert_id": 123,
  "force_recalculation": true
}
```

## 🔍 Surveillance et maintenance

### Logs à surveiller
```bash
# Logs de l'application
tail -f logs.json

# Logs de maintenance (Windows)
type maintenance_last_run.log

# Logs de maintenance (Linux)
tail -f maintenance.log
```

### Commandes utiles

#### Windows
```powershell
# Exécuter maintenance manuellement
python maintenance_tasks.py --tasks transitions scoring cleanup

# Voir les tâches planifiées
Get-ScheduledTask | Where-Object {$_.TaskName -like "*Typosquatting*"}

# Démarrer une tâche manuellement
Start-ScheduledTask -TaskName "Typosquatting-Maintenance"
```

#### Linux
```bash
# Exécuter maintenance manuellement
python3 maintenance_tasks.py --tasks transitions scoring cleanup

# Voir les tâches cron
crontab -l

# Voir les logs de cron
sudo journalctl -u cron -f
```

## 🆘 Dépannage rapide

### Problèmes courants

#### "Module config not found"
```bash
# Vérifier que config.py existe
ls -la config.py

# Si manquant, relancer le déploiement
python deploy_improvements.py
```

#### "Database migration failed"
```bash
# Vérifier la connexion à la base
python -c "import psycopg2; print('DB OK')"

# Relancer uniquement la migration
python deploy_improvements.py --skip-migration
```

#### "Scheduled tasks not working"

**Windows :**
```powershell
# Vérifier les permissions
Get-ScheduledTask -TaskName "*Typosquatting*" | Get-ScheduledTaskInfo

# Reconfigurer
.\setup_scheduled_tasks.ps1 -Remove
.\setup_scheduled_tasks.ps1
```

**Linux :**
```bash
# Vérifier cron
sudo systemctl status cron

# Reconfigurer
./setup_scheduled_tasks.sh --remove
./setup_scheduled_tasks.sh
```

## 📚 Documentation complète

- **README.md** : Documentation technique détaillée
- **GUIDE_UTILISATEUR.md** : Guide utilisateur complet
- **IMPLEMENTATION_COMPLETE.md** : Résumé de toutes les fonctionnalités

## 🎉 Félicitations !

Votre système de typosquatting est maintenant équipé de :
- 🤖 **Scoring automatique** intelligent
- 🔄 **Transitions d'état** automatiques
- 📊 **Tableaux de bord** enrichis
- 🛠️ **Maintenance** automatisée
- 📈 **Historique** complet

Le système fonctionne maintenant de manière largement autonome avec un minimum d'intervention manuelle !

---

**Support** : Consultez les fichiers de documentation pour plus de détails ou en cas de problème.