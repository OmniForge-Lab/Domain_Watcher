// Système de scoring de risque - Frontend

// Configuration des couleurs et seuils
const RISK_CONFIG = {
    thresholds: {
        low: 30,
        medium: 70,
        high: 100
    },
    colors: {
        low: '#28a745',    // Vert
        medium: '#ffc107', // Jaune
        high: '#dc3545'    // Rouge
    },
    states: {
        'nouveau': { color: '#ffc107', label: 'Nouveau' },
        'investigating': { color: '#17a2b8', label: 'En investigation' },
        'monitoring': { color: '#6c757d', label: 'Surveillance' },
        'action_required': { color: '#dc3545', label: 'Action requise' },
        'escalated': { color: '#dc3545', label: 'Escaladé' },
        'legitimate': { color: '#28a745', label: 'Légitime' },
        'parked': { color: '#e9ecef', label: 'Parqué' },
        'expired': { color: '#e9ecef', label: 'Expiré' },
        'resolved': { color: '#28a745', label: 'Résolu' },
        'false_positive': { color: '#6c757d', label: 'Faux positif' },
        'blocked': { color: '#343a40', label: 'Bloqué' }
    }
};

// Fonction pour obtenir la couleur du risque
function getRiskColor(score) {
    if (score < RISK_CONFIG.thresholds.low) {
        return RISK_CONFIG.colors.low;
    } else if (score < RISK_CONFIG.thresholds.medium) {
        return RISK_CONFIG.colors.medium;
    } else {
        return RISK_CONFIG.colors.high;
    }
}

// Fonction pour obtenir le niveau de risque
function getRiskLevel(score) {
    if (score < RISK_CONFIG.thresholds.low) {
        return 'FAIBLE';
    } else if (score < RISK_CONFIG.thresholds.medium) {
        return 'MOYEN';
    } else {
        return 'ÉLEVÉ';
    }
}

// Fonction pour calculer et afficher le score de risque
async function calculateRiskScore(domain, originalDomain = null) {
    try {
        // Afficher un indicateur de chargement
        updateRiskScoreDisplay('Calcul en cours...', 0, 'secondary');
        
        const url = `/risk_score?domain=${encodeURIComponent(domain)}${originalDomain ? `&original_domain=${encodeURIComponent(originalDomain)}` : ''}`;
        const response = await fetch(url);
        
        if (!response.ok) {
            throw new Error(`HTTP error! status: ${response.status}`);
        }
        
        const data = await response.json();
        
        if (data.error) {
            updateRiskScoreDisplay('Erreur de calcul', 0, 'danger');
            console.error('Risk score calculation error:', data.error);
            return null;
        }
        
        // Afficher le score calculé
        const score = data.risk_assessment.overall_score;
        const riskLevel = getRiskLevel(score);
        const color = getRiskColor(score);
        
        updateRiskScoreDisplay(riskLevel, score, getBootstrapColorClass(color));
        
        // Afficher les détails des composants
        displayRiskComponents(data.risk_assessment.components);
        
        // Afficher les recommandations
        displayRecommendations(data.recommended_action, data.recommended_status);
        
        return data;
        
    } catch (error) {
        console.error('Error calculating risk score:', error);
        updateRiskScoreDisplay('Erreur', 0, 'danger');
        return null;
    }
}

// Fonction pour mettre à jour l'affichage du score de risque
function updateRiskScoreDisplay(level, score, colorClass) {
    const scoreElement = document.getElementById('riskScore');
    const levelElement = document.getElementById('riskLevel');
    const progressElement = document.getElementById('riskProgress');
    
    if (scoreElement) {
        scoreElement.textContent = score.toFixed(1);
        scoreElement.className = `badge badge-${colorClass}`;
    }
    
    if (levelElement) {
        levelElement.textContent = level;
        levelElement.className = `text-${colorClass}`;
    }
    
    if (progressElement) {
        progressElement.style.width = `${score}%`;
        progressElement.className = `progress-bar bg-${colorClass}`;
        progressElement.setAttribute('aria-valuenow', score);
    }
}

// Fonction pour afficher les composants du score
function displayRiskComponents(components) {
    const container = document.getElementById('riskComponents');
    if (!container) return;
    
    container.innerHTML = '';
    
    const componentLabels = {
        similarity: 'Similarité',
        domain_age: 'Âge du domaine',
        geolocation: 'Géolocalisation',
        ssl: 'Certificat SSL',
        reputation: 'Réputation'
    };
    
    Object.entries(components).forEach(([key, value]) => {
        const label = componentLabels[key] || key;
        const color = getRiskColor(value);
        const colorClass = getBootstrapColorClass(color);
        
        const componentHtml = `
            <div class="d-flex justify-content-between align-items-center mb-2">
                <span class="small">${label}:</span>
                <span class="badge badge-${colorClass}">${value.toFixed(1)}</span>
            </div>
        `;
        
        container.innerHTML += componentHtml;
    });
}

// Fonction pour afficher les recommandations
function displayRecommendations(action, status) {
    const actionElement = document.getElementById('recommendedAction');
    const statusElement = document.getElementById('recommendedStatus');
    
    const actionLabels = {
        'passive_monitoring': 'Surveillance passive',
        'moderate_alert': 'Alerte modérée',
        'immediate_action': 'Action immédiate'
    };
    
    if (actionElement) {
        actionElement.textContent = actionLabels[action] || action;
    }
    
    if (statusElement && RISK_CONFIG.states[status]) {
        const stateConfig = RISK_CONFIG.states[status];
        statusElement.textContent = stateConfig.label;
        statusElement.style.color = stateConfig.color;
    }
}

// Fonction utilitaire pour convertir les couleurs hex en classes Bootstrap
function getBootstrapColorClass(hexColor) {
    switch (hexColor) {
        case '#28a745': return 'success';
        case '#ffc107': return 'warning';
        case '#dc3545': return 'danger';
        case '#17a2b8': return 'info';
        case '#6c757d': return 'secondary';
        default: return 'primary';
    }
}

// Fonction pour mettre à jour le score d'une alerte
async function updateAlertScore(alertId) {
    try {
        const response = await fetch('/update_alert_score', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({ alert_id: alertId })
        });
        
        if (!response.ok) {
            throw new Error(`HTTP error! status: ${response.status}`);
        }
        
        const data = await response.json();
        
        if (data.success) {
            // Mettre à jour l'affichage du score dans la liste des alertes
            const alertRow = document.querySelector(`tr[data-alert-id="${alertId}"]`);
            if (alertRow) {
                const scoreCell = alertRow.querySelector('.risk-score');
                if (scoreCell) {
                    const color = getRiskColor(data.new_score);
                    const colorClass = getBootstrapColorClass(color);
                    scoreCell.innerHTML = `<span class="badge badge-${colorClass}">${data.new_score.toFixed(1)}</span>`;
                }
            }
            
            showNotification('Score mis à jour avec succès', 'success');
        } else {
            showNotification('Erreur lors de la mise à jour du score', 'error');
        }
        
    } catch (error) {
        console.error('Error updating alert score:', error);
        showNotification('Erreur lors de la mise à jour du score', 'error');
    }
}

// Fonction pour afficher une notification
function showNotification(message, type) {
    const alertClass = type === 'success' ? 'alert-success' : 'alert-danger';
    const notification = `
        <div class="alert ${alertClass} alert-dismissible fade show" role="alert">
            ${message}
            <button type="button" class="close" data-dismiss="alert" aria-label="Close">
                <span aria-hidden="true">&times;</span>
            </button>
        </div>
    `;
    
    const container = document.getElementById('notifications') || document.body;
    container.insertAdjacentHTML('afterbegin', notification);
    
    // Auto-dismiss après 5 secondes
    setTimeout(() => {
        const alert = container.querySelector('.alert');
        if (alert) {
            alert.remove();
        }
    }, 5000);
}

// Fonction pour initialiser le système de scoring sur une page
function initializeRiskScoring() {
    // Ajouter des event listeners pour les boutons de calcul de score
    document.querySelectorAll('.calculate-risk-btn').forEach(button => {
        button.addEventListener('click', async (e) => {
            e.preventDefault();
            const domain = button.dataset.domain;
            const originalDomain = button.dataset.originalDomain;
            await calculateRiskScore(domain, originalDomain);
        });
    });
    
    // Ajouter des event listeners pour les boutons de mise à jour de score
    document.querySelectorAll('.update-score-btn').forEach(button => {
        button.addEventListener('click', async (e) => {
            e.preventDefault();
            const alertId = parseInt(button.dataset.alertId);
            await updateAlertScore(alertId);
        });
    });
}

// Initialiser quand le DOM est chargé
document.addEventListener('DOMContentLoaded', initializeRiskScoring);

// Exporter les fonctions pour utilisation globale
window.RiskScoring = {
    calculateRiskScore,
    updateAlertScore,
    getRiskColor,
    getRiskLevel,
    initializeRiskScoring
};