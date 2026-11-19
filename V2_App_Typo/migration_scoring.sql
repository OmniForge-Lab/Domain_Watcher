-- Migration pour ajouter le système de scoring
-- À exécuter sur la base de données existante

-- 1. Ajouter les colonnes de scoring à la table alerts
ALTER TABLE alerts ADD COLUMN IF NOT EXISTS risk_score DECIMAL(5,2) DEFAULT 0;
ALTER TABLE alerts ADD COLUMN IF NOT EXISTS last_analysis TIMESTAMP;
ALTER TABLE alerts ADD COLUMN IF NOT EXISTS similarity_score DECIMAL(5,2);
ALTER TABLE alerts ADD COLUMN IF NOT EXISTS domain_age_score DECIMAL(5,2);
ALTER TABLE alerts ADD COLUMN IF NOT EXISTS geolocation_score DECIMAL(5,2);
ALTER TABLE alerts ADD COLUMN IF NOT EXISTS ssl_score DECIMAL(5,2);
ALTER TABLE alerts ADD COLUMN IF NOT EXISTS reputation_score DECIMAL(5,2);
ALTER TABLE alerts ADD COLUMN IF NOT EXISTS recommended_action VARCHAR(50);
ALTER TABLE alerts ADD COLUMN IF NOT EXISTS risk_level VARCHAR(20);

-- 2. Créer une table pour l'historique des scores
CREATE TABLE IF NOT EXISTS risk_score_history (
    id SERIAL PRIMARY KEY,
    alert_id INTEGER REFERENCES alerts(id) ON DELETE CASCADE,
    risk_score DECIMAL(5,2) NOT NULL,
    similarity_score DECIMAL(5,2),
    domain_age_score DECIMAL(5,2),
    geolocation_score DECIMAL(5,2),
    ssl_score DECIMAL(5,2),
    reputation_score DECIMAL(5,2),
    calculation_date TIMESTAMP DEFAULT NOW(),
    notes TEXT
);

-- 3. Créer une table de configuration pour les seuils de scoring
CREATE TABLE IF NOT EXISTS scoring_config (
    id SERIAL PRIMARY KEY,
    config_name VARCHAR(100) UNIQUE NOT NULL,
    config_value JSONB NOT NULL,
    description TEXT,
    created_at TIMESTAMP DEFAULT NOW(),
    updated_at TIMESTAMP DEFAULT NOW()
);

-- 4. Insérer les valeurs par défaut de configuration
INSERT INTO scoring_config (config_name, config_value, description) VALUES
('similarity_weight', '0.30', 'Poids du score de similarité dans le calcul global'),
('domain_age_weight', '0.20', 'Poids du score d''âge de domaine dans le calcul global'),
('geolocation_weight', '0.15', 'Poids du score de géolocalisation dans le calcul global'),
('ssl_weight', '0.15', 'Poids du score SSL dans le calcul global'),
('reputation_weight', '0.20', 'Poids du score de réputation dans le calcul global')
ON CONFLICT (config_name) DO NOTHING;

-- 5. Créer une table pour les états d'alerte
CREATE TABLE IF NOT EXISTS alert_states (
    id SERIAL PRIMARY KEY,
    state_code VARCHAR(20) UNIQUE NOT NULL,
    state_label VARCHAR(50) NOT NULL,
    description TEXT,
    color_code VARCHAR(7) DEFAULT '#000000',
    priority INTEGER DEFAULT 0,
    is_active BOOLEAN DEFAULT true,
    created_at TIMESTAMP DEFAULT NOW()
);

-- 6. Insérer les états d'alerte par défaut
INSERT INTO alert_states (state_code, state_label, description, color_code, priority) VALUES
('nouveau', 'Nouveau', 'Alerte nouvellement détectée', '#ff6b6b', 1),
('en_cours', 'En cours', 'Alerte en cours d''analyse', '#feca57', 2),
('monitoring', 'Surveillance', 'Domaine sous surveillance', '#48dbfb', 3),
('suspect', 'Suspect', 'Domaine potentiellement malveillant', '#ff9ff3', 4),
('malveillant', 'Malveillant', 'Domaine confirmé comme malveillant', '#ee5a24', 5),
('bloque', 'Bloqué', 'Domaine bloqué', '#2d3436', 6),
('faux_positif', 'Faux positif', 'Alerte confirmée comme faux positif', '#00b894', 7),
('resolu', 'Résolu', 'Alerte résolue', '#6c5ce7', 8),
('legitime', 'Légitime', 'Domaine confirmé comme légitime', '#a29bfe', 9),
('expire', 'Expiré', 'Domaine expiré ou inaccessible', '#636e72', 10),
('archive', 'Archivé', 'Alerte archivée', '#b2bec3', 11)
ON CONFLICT (state_code) DO NOTHING;

-- 7. Créer une table pour l'historique des changements d'état
CREATE TABLE IF NOT EXISTS alert_status_history (
    id SERIAL PRIMARY KEY,
    alert_id INTEGER REFERENCES alerts(id) ON DELETE CASCADE,
    old_status VARCHAR(20),
    new_status VARCHAR(20),
    changed_by VARCHAR(100),
    change_reason TEXT,
    changed_at TIMESTAMP DEFAULT NOW()
);

-- 8. Créer les index pour optimiser les performances
CREATE INDEX IF NOT EXISTS idx_alerts_risk_score ON alerts(risk_score);
CREATE INDEX IF NOT EXISTS idx_alerts_last_analysis ON alerts(last_analysis);
CREATE INDEX IF NOT EXISTS idx_alerts_status ON alerts(status);
CREATE INDEX IF NOT EXISTS idx_risk_score_history_alert_id ON risk_score_history(alert_id);
CREATE INDEX IF NOT EXISTS idx_risk_score_history_date ON risk_score_history(calculation_date);
CREATE INDEX IF NOT EXISTS idx_alert_status_history_alert_id ON alert_status_history(alert_id);
CREATE INDEX IF NOT EXISTS idx_alert_status_history_date ON alert_status_history(changed_at);

-- 9. Créer une vue pour les statistiques de scoring
CREATE OR REPLACE VIEW scoring_statistics AS
SELECT 
    COUNT(*) as total_alerts,
    AVG(risk_score) as avg_risk_score,
    COUNT(CASE WHEN risk_score < 30 THEN 1 END) as low_risk_count,
    COUNT(CASE WHEN risk_score >= 30 AND risk_score < 70 THEN 1 END) as medium_risk_count,
    COUNT(CASE WHEN risk_score >= 70 THEN 1 END) as high_risk_count,
    COUNT(CASE WHEN last_analysis IS NULL THEN 1 END) as unanalyzed_count,
    COUNT(CASE WHEN last_analysis > NOW() - INTERVAL '24 hours' THEN 1 END) as analyzed_today
FROM alerts
WHERE status NOT IN ('resolved', 'false_positive', 'blocked');

-- 10. Créer une vue pour les alertes avec informations complètes
CREATE OR REPLACE VIEW alerts_detailed AS
SELECT 
    a.*,
    wd.domain as watched_domain,
    wd.distance_threshold,
    ast.state_label,
    ast.description as status_description,
    ast.color_code as status_color,
    ast.priority as status_priority,
    CASE 
        WHEN a.risk_score < 30 THEN 'LOW'
        WHEN a.risk_score < 70 THEN 'MEDIUM'
        ELSE 'HIGH'
    END as risk_category,
    CASE 
        WHEN a.last_analysis IS NULL THEN 'NEVER'
        WHEN a.last_analysis > NOW() - INTERVAL '24 hours' THEN 'RECENT'
        WHEN a.last_analysis > NOW() - INTERVAL '7 days' THEN 'WEEK'
        ELSE 'OLD'
    END as analysis_freshness
FROM alerts a
LEFT JOIN watched_domains wd ON a.watched_domain_id = wd.id
LEFT JOIN alert_states ast ON a.status = ast.state_code;

-- 11. Créer une fonction pour calculer automatiquement les transitions d'état
CREATE OR REPLACE FUNCTION auto_transition_alerts()
RETURNS INTEGER AS $$
DECLARE
    transition_count INTEGER := 0;
    alert_record RECORD;
BEGIN
    -- Transition nouveau -> monitoring pour les scores faibles après 7 jours
    FOR alert_record IN 
        SELECT id, detected_domain FROM alerts 
        WHERE status = 'nouveau' 
        AND risk_score < 30 
        AND detection_date < NOW() - INTERVAL '7 days'
    LOOP
        UPDATE alerts SET status = 'monitoring' WHERE id = alert_record.id;
        
        INSERT INTO alert_status_history (alert_id, old_status, new_status, changed_by, change_reason)
        VALUES (alert_record.id, 'nouveau', 'monitoring', 'SYSTEM', 'Auto-transition: score faible après 7 jours');
        
        transition_count := transition_count + 1;
    END LOOP;
    
    -- Transition monitoring -> legitimate pour les domaines stables après 90 jours
    FOR alert_record IN 
        SELECT id, detected_domain FROM alerts 
        WHERE status = 'monitoring' 
        AND risk_score < 20 
        AND detection_date < NOW() - INTERVAL '90 days'
        AND last_analysis > NOW() - INTERVAL '7 days' -- Analysé récemment
    LOOP
        UPDATE alerts SET status = 'legitimate' WHERE id = alert_record.id;
        
        INSERT INTO alert_status_history (alert_id, old_status, new_status, changed_by, change_reason)
        VALUES (alert_record.id, 'monitoring', 'legitimate', 'SYSTEM', 'Auto-transition: domaine stable après 90 jours');
        
        transition_count := transition_count + 1;
    END LOOP;
    
    RETURN transition_count;
END;
$$ LANGUAGE plpgsql;

-- 12. Créer une fonction pour nettoyer les anciennes données
CREATE OR REPLACE FUNCTION cleanup_old_data()
RETURNS INTEGER AS $$
DECLARE
    cleanup_count INTEGER := 0;
    temp_count INTEGER;
BEGIN
    -- Supprimer l'historique des scores de plus de 1 an
    DELETE FROM risk_score_history 
    WHERE calculation_date < NOW() - INTERVAL '1 year';
    
    GET DIAGNOSTICS temp_count = ROW_COUNT;
    cleanup_count := cleanup_count + temp_count;
    
    -- Supprimer l'historique des changements d'état de plus de 2 ans
    DELETE FROM alert_status_history 
    WHERE changed_at < NOW() - INTERVAL '2 years';
    
    GET DIAGNOSTICS temp_count = ROW_COUNT;
    cleanup_count := cleanup_count + temp_count;
    
    RETURN cleanup_count;
END;
$$ LANGUAGE plpgsql;

-- 13. Mettre à jour les statuts existants si nécessaire
UPDATE alerts SET status = 'nouveau' WHERE status IS NULL OR status = '';
UPDATE alerts SET risk_score = 0 WHERE risk_score IS NULL;
UPDATE alerts SET risk_level = 'LOW' WHERE risk_level IS NULL AND risk_score < 30;
UPDATE alerts SET risk_level = 'MEDIUM' WHERE risk_level IS NULL AND risk_score >= 30 AND risk_score < 70;
UPDATE alerts SET risk_level = 'HIGH' WHERE risk_level IS NULL AND risk_score >= 70;

-- 14. Ajouter des commentaires sur les nouvelles colonnes
COMMENT ON COLUMN alerts.risk_score IS 'Score de risque global calculé (0-100)';
COMMENT ON COLUMN alerts.similarity_score IS 'Score de similarité avec le domaine surveillé';
COMMENT ON COLUMN alerts.domain_age_score IS 'Score basé sur l''âge du domaine';
COMMENT ON COLUMN alerts.geolocation_score IS 'Score basé sur la géolocalisation';
COMMENT ON COLUMN alerts.ssl_score IS 'Score basé sur le certificat SSL';
COMMENT ON COLUMN alerts.reputation_score IS 'Score de réputation (VirusTotal, etc.)';
COMMENT ON COLUMN alerts.last_analysis IS 'Date de la dernière analyse complète';
COMMENT ON COLUMN alerts.recommended_action IS 'Action recommandée basée sur le score';
COMMENT ON COLUMN alerts.risk_level IS 'Niveau de risque (LOW/MEDIUM/HIGH)';

-- 15. Afficher un résumé de la migration
SELECT 
    'Migration terminée' as status,
    (SELECT COUNT(*) FROM alerts) as total_alerts,
    (SELECT COUNT(*) FROM alert_states) as alert_states_count,
    (SELECT COUNT(*) FROM scoring_config) as config_entries;