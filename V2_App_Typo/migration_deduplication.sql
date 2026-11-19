-- Migration pour ajouter une contrainte d'unicité et éviter les doublons
-- Exécuter après avoir nettoyé les doublons existants

-- Ajouter un index unique pour éviter les doublons futurs
-- Combinaison de watched_domain_id et detected_domain doit être unique
CREATE UNIQUE INDEX IF NOT EXISTS idx_alerts_unique_domain 
ON alerts (watched_domain_id, detected_domain);

-- Ajouter un commentaire pour documenter la contrainte
COMMENT ON INDEX idx_alerts_unique_domain IS 'Index unique pour éviter les doublons d''alertes sur la même combinaison domaine surveillé/domaine détecté';

-- Optionnel: Ajouter une contrainte CHECK pour s'assurer que detected_domain n'est pas vide
ALTER TABLE alerts ADD CONSTRAINT chk_detected_domain_not_empty 
CHECK (detected_domain IS NOT NULL AND detected_domain != '');