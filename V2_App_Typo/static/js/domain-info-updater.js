/**
 * Fonction pour mettre à jour les informations d'un domaine (IP, registrar, etc.)
 * @param {number} alertId - L'ID de l'alerte à mettre à jour
 */
function updateDomainInfo(alertId) {
    // Afficher un message de chargement
    showToast('Mise à jour des informations en cours...', 'info');
    
    // Appeler l'API pour mettre à jour les informations
    fetch(`/update_domain_info?alert_id=${alertId}`)
        .then(response => response.json())
        .then(data => {
            if (data.message) {
                showToast('Informations mises à jour avec succès', 'success');
                // Recharger les alertes pour afficher les nouvelles informations
                if (typeof loadAlerts === 'function') {
                    loadAlerts();
                } else if (typeof refreshAlertDetails === 'function') {
                    refreshAlertDetails(alertId);
                } else {
                    // Recharger la page si aucune fonction de rechargement n'est disponible
                    setTimeout(() => {
                        window.location.reload();
                    }, 1000);
                }
            } else if (data.error) {
                showToast(`Erreur: ${data.error}`, 'error');
            }
        })
        .catch(error => {
            console.error('Error:', error);
            showToast('Erreur lors de la mise à jour des informations', 'error');
        });
}

/**
 * Fonction pour mettre à jour automatiquement toutes les alertes sans informations
 */
function updateAllMissingInfo() {
    showToast('Mise à jour de toutes les alertes en cours...', 'info');
    
    fetch('/update_domain_info')
        .then(response => response.json())
        .then(data => {
            if (data.message) {
                showToast(data.message, 'success');
                // Recharger les alertes
                if (typeof loadAlerts === 'function') {
                    loadAlerts();
                } else {
                    // Recharger la page
                    setTimeout(() => {
                        window.location.reload();
                    }, 1000);
                }
            } else if (data.error) {
                showToast(`Erreur: ${data.error}`, 'error');
            }
        })
        .catch(error => {
            console.error('Error:', error);
            showToast('Erreur lors de la mise à jour des informations', 'error');
        });
}