#!/bin/bash

# Script bash pour configurer les tâches planifiées du système de typosquatting
# Compatible avec les systèmes Linux utilisant cron

set -e

# Configuration par défaut
APP_PATH="$(pwd)"
TASK_NAME="typosquatting-maintenance"
SCHEDULE_TIME="02:00"
REMOVE=false
TEST=false

# Couleurs pour l'affichage
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
GRAY='\033[0;37m'
NC='\033[0m' # No Color

# Fonction d'aide
show_help() {
    echo "Usage: $0 [OPTIONS]"
    echo "Options:"
    echo "  --app-path PATH     Chemin de l'application (défaut: répertoire courant)"
    echo "  --schedule-time HH:MM  Heure d'exécution quotidienne (défaut: 02:00)"
    echo "  --remove            Supprimer les tâches planifiées"
    echo "  --test              Tester les tâches planifiées"
    echo "  --help              Afficher cette aide"
    echo ""
    echo "Exemples:"
    echo "  $0                                    # Configuration standard"
    echo "  $0 --schedule-time 03:30              # Exécution à 3h30"
    echo "  $0 --app-path /opt/typosquatting      # Chemin personnalisé"
    echo "  $0 --remove                           # Supprimer les tâches"
    echo "  $0 --test                             # Tester les tâches"
}

# Analyse des arguments
while [[ $# -gt 0 ]]; do
    case $1 in
        --app-path)
            APP_PATH="$2"
            shift 2
            ;;
        --schedule-time)
            SCHEDULE_TIME="$2"
            shift 2
            ;;
        --remove)
            REMOVE=true
            shift
            ;;
        --test)
            TEST=true
            shift
            ;;
        --help)
            show_help
            exit 0
            ;;
        *)
            echo -e "${RED}❌ Option inconnue: $1${NC}"
            show_help
            exit 1
            ;;
    esac
done

# Fonction pour afficher les messages colorés
log_info() {
    echo -e "${BLUE}ℹ️  $1${NC}"
}

log_success() {
    echo -e "${GREEN}✅ $1${NC}"
}

log_warning() {
    echo -e "${YELLOW}⚠️  $1${NC}"
}

log_error() {
    echo -e "${RED}❌ $1${NC}"
}

log_cyan() {
    echo -e "${CYAN}🔧 $1${NC}"
}

# Vérifier les prérequis
check_prerequisites() {
    log_cyan "Vérification des prérequis..."
    
    # Vérifier que le répertoire existe
    if [[ ! -d "$APP_PATH" ]]; then
        log_error "Le répertoire '$APP_PATH' n'existe pas"
        exit 1
    fi
    
    # Vérifier que cron est installé
    if ! command -v crontab &> /dev/null; then
        log_error "crontab n'est pas installé. Installez cron d'abord."
        log_info "Ubuntu/Debian: sudo apt-get install cron"
        log_info "CentOS/RHEL: sudo yum install cronie"
        exit 1
    fi
    
    # Vérifier que les fichiers nécessaires existent
    local required_files=("maintenance_tasks.py" "config.py")
    
    for file in "${required_files[@]}"; do
        if [[ -f "$APP_PATH/$file" ]]; then
            log_success "$file trouvé"
        else
            log_error "Fichier requis manquant: $file"
            exit 1
        fi
    done
    
    # Vérifier Python
    if ! command -v python3 &> /dev/null; then
        log_error "Python3 n'est pas installé"
        exit 1
    fi
    
    log_success "Prérequis vérifiés"
}

# Créer le script de maintenance
create_maintenance_script() {
    log_cyan "Création du script de maintenance..."
    
    local script_path="$APP_PATH/run_maintenance.sh"
    
    cat > "$script_path" << EOF
#!/bin/bash
# Script de maintenance du système de typosquatting
# Généré automatiquement

set -e

# Répertoire de l'application
cd "$APP_PATH"

# Log de début
echo "[\$(date '+%Y-%m-%d %H:%M:%S')] Début de la maintenance" >> maintenance.log

# Activer l'environnement virtuel si il existe
if [[ -f "venv/bin/activate" ]]; then
    source venv/bin/activate
    echo "[\$(date '+%Y-%m-%d %H:%M:%S')] Environnement virtuel activé" >> maintenance.log
fi

# Exécuter les tâches de maintenance
if python3 maintenance_tasks.py --tasks transitions scoring cleanup report notification >> maintenance.log 2>&1; then
    echo "[\$(date '+%Y-%m-%d %H:%M:%S')] Maintenance terminée avec succès" >> maintenance.log
else
    echo "[\$(date '+%Y-%m-%d %H:%M:%S')] Erreur lors de la maintenance" >> maintenance.log
    exit 1
fi

# Log de fin
echo "[\$(date '+%Y-%m-%d %H:%M:%S')] Fin de la maintenance" >> maintenance.log
EOF

    chmod +x "$script_path"
    log_success "Script de maintenance créé: $script_path"
}

# Créer le script de surveillance
create_monitoring_script() {
    log_cyan "Création du script de surveillance..."
    
    local script_path="$APP_PATH/run_monitoring.sh"
    
    cat > "$script_path" << EOF
#!/bin/bash
# Script de surveillance du système de typosquatting
# Généré automatiquement

set -e

# Répertoire de l'application
cd "$APP_PATH"

# Activer l'environnement virtuel si il existe
if [[ -f "venv/bin/activate" ]]; then
    source venv/bin/activate
fi

# Exécuter les transitions automatiques (mode silencieux)
python3 maintenance_tasks.py --tasks transitions --quiet >> monitoring.log 2>&1 || true
EOF

    chmod +x "$script_path"
    log_success "Script de surveillance créé: $script_path"
}

# Configurer les tâches cron
setup_cron_jobs() {
    log_cyan "Configuration des tâches cron..."
    
    # Convertir l'heure au format cron
    local hour=$(echo "$SCHEDULE_TIME" | cut -d':' -f1)
    local minute=$(echo "$SCHEDULE_TIME" | cut -d':' -f2)
    
    # Supprimer les anciennes tâches
    crontab -l 2>/dev/null | grep -v "typosquatting" | crontab - 2>/dev/null || true
    
    # Créer le nouveau crontab
    local temp_cron=$(mktemp)
    
    # Récupérer le crontab existant (sans les tâches typosquatting)
    crontab -l 2>/dev/null | grep -v "typosquatting" > "$temp_cron" || true
    
    # Ajouter les nouvelles tâches
    echo "# Tâches de maintenance du système de typosquatting" >> "$temp_cron"
    echo "$minute $hour * * * $APP_PATH/run_maintenance.sh # typosquatting-maintenance" >> "$temp_cron"
    echo "0 * * * * $APP_PATH/run_monitoring.sh # typosquatting-monitoring" >> "$temp_cron"
    echo "" >> "$temp_cron"
    
    # Installer le nouveau crontab
    crontab "$temp_cron"
    rm "$temp_cron"
    
    log_success "Tâches cron configurées"
    log_info "Maintenance quotidienne: $SCHEDULE_TIME"
    log_info "Surveillance: Toutes les heures"
}

# Supprimer les tâches cron
remove_cron_jobs() {
    log_cyan "Suppression des tâches cron..."
    
    # Supprimer les tâches typosquatting du crontab
    crontab -l 2>/dev/null | grep -v "typosquatting" | crontab - 2>/dev/null || true
    
    # Supprimer les scripts
    rm -f "$APP_PATH/run_maintenance.sh"
    rm -f "$APP_PATH/run_monitoring.sh"
    
    log_success "Tâches supprimées"
}

# Tester les tâches
test_tasks() {
    log_cyan "Test des tâches planifiées..."
    
    # Vérifier que les scripts existent
    if [[ -f "$APP_PATH/run_maintenance.sh" ]]; then
        log_success "Script de maintenance trouvé"
        
        # Tester l'exécution
        log_info "Test d'exécution du script de maintenance..."
        if bash "$APP_PATH/run_maintenance.sh"; then
            log_success "Script de maintenance exécuté avec succès"
        else
            log_warning "Erreur lors de l'exécution du script de maintenance"
        fi
    else
        log_error "Script de maintenance non trouvé"
    fi
    
    if [[ -f "$APP_PATH/run_monitoring.sh" ]]; then
        log_success "Script de surveillance trouvé"
        
        # Tester l'exécution
        log_info "Test d'exécution du script de surveillance..."
        if bash "$APP_PATH/run_monitoring.sh"; then
            log_success "Script de surveillance exécuté avec succès"
        else
            log_warning "Erreur lors de l'exécution du script de surveillance"
        fi
    else
        log_error "Script de surveillance non trouvé"
    fi
    
    # Afficher les tâches cron
    log_info "Tâches cron actuelles:"
    crontab -l 2>/dev/null | grep "typosquatting" || log_warning "Aucune tâche typosquatting trouvée"
}

# Afficher le statut des tâches
show_status() {
    log_cyan "Statut des tâches planifiées:"
    
    # Vérifier les scripts
    echo -e "\n${CYAN}📋 Scripts:${NC}"
    if [[ -f "$APP_PATH/run_maintenance.sh" ]]; then
        echo -e "   ${GREEN}✅ run_maintenance.sh${NC}"
    else
        echo -e "   ${RED}❌ run_maintenance.sh${NC}"
    fi
    
    if [[ -f "$APP_PATH/run_monitoring.sh" ]]; then
        echo -e "   ${GREEN}✅ run_monitoring.sh${NC}"
    else
        echo -e "   ${RED}❌ run_monitoring.sh${NC}"
    fi
    
    # Vérifier les tâches cron
    echo -e "\n${CYAN}⏰ Tâches cron:${NC}"
    local cron_tasks=$(crontab -l 2>/dev/null | grep "typosquatting" || true)
    if [[ -n "$cron_tasks" ]]; then
        echo "$cron_tasks" | while read -r line; do
            echo -e "   ${GREEN}✅${NC} $line"
        done
    else
        echo -e "   ${RED}❌ Aucune tâche configurée${NC}"
    fi
    
    # Vérifier les logs
    echo -e "\n${CYAN}📄 Logs récents:${NC}"
    if [[ -f "$APP_PATH/maintenance.log" ]]; then
        echo -e "   ${GREEN}✅ maintenance.log${NC}"
        tail -3 "$APP_PATH/maintenance.log" 2>/dev/null | sed 's/^/      /' || true
    else
        echo -e "   ${GRAY}ℹ️  maintenance.log (pas encore créé)${NC}"
    fi
    
    if [[ -f "$APP_PATH/monitoring.log" ]]; then
        echo -e "   ${GREEN}✅ monitoring.log${NC}"
    else
        echo -e "   ${GRAY}ℹ️  monitoring.log (pas encore créé)${NC}"
    fi
}

# Fonction principale
main() {
    echo -e "${GREEN}🔧 CONFIGURATION DES TÂCHES PLANIFIÉES - SYSTÈME DE TYPOSQUATTING${NC}"
    echo "======================================================================"
    echo -e "${CYAN}Répertoire de l'application: $APP_PATH${NC}"
    echo ""
    
    # Vérifier les prérequis
    check_prerequisites
    
    if [[ "$REMOVE" == true ]]; then
        remove_cron_jobs
        log_success "Suppression terminée"
        return 0
    fi
    
    if [[ "$TEST" == true ]]; then
        test_tasks
        show_status
        return 0
    fi
    
    # Configuration normale
    create_maintenance_script
    create_monitoring_script
    setup_cron_jobs
    
    echo ""
    echo "======================================================================"
    log_success "Configuration terminée avec succès!"
    
    echo -e "\n${CYAN}📋 Résumé:${NC}"
    echo -e "   • Maintenance quotidienne: $SCHEDULE_TIME"
    echo -e "   • Surveillance: Toutes les heures"
    echo -e "   • Scripts créés dans: $APP_PATH"
    
    echo -e "\n${CYAN}🔧 Commandes utiles:${NC}"
    echo -e "   • Tester: $0 --test"
    echo -e "   • Supprimer: $0 --remove"
    echo -e "   • Voir les tâches: crontab -l | grep typosquatting"
    echo -e "   • Voir les logs: tail -f $APP_PATH/maintenance.log"
    
    echo ""
    show_status
}

# Exécution
main "$@"