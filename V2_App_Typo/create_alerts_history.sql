-- Script pour créer la table alerts_history
-- Cette table stockera les domaines archivés depuis le dashboard

CREATE TABLE IF NOT EXISTS alerts_history (
    id SERIAL PRIMARY KEY,
    original_alert_id INTEGER NOT NULL, -- ID de l'alerte originale
    source TEXT,
    watched_domain_id INTEGER,
    detected_domain TEXT NOT NULL,
    lev_distance INTEGER,
    dns_a TEXT,
    dns_mx TEXT,
    dns_ns TEXT,
    whois_created TEXT,
    whois_registrar TEXT,
    issuer TEXT,
    email TEXT,
    detection_date TIMESTAMP,
    original_status TEXT, -- Statut au moment de l'archivage
    comment TEXT,
    screenshot_path TEXT,
    risk_score DECIMAL(5,2),
    archived_date TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    archived_reason TEXT DEFAULT 'manual_archive', -- Raison de l'archivage
    archived_by TEXT DEFAULT 'dashboard_user' -- Qui a archivé
);

-- Index pour améliorer les performances
CREATE INDEX IF NOT EXISTS idx_alerts_history_original_id ON alerts_history(original_alert_id);
CREATE INDEX IF NOT EXISTS idx_alerts_history_detected_domain ON alerts_history(detected_domain);
CREATE INDEX IF NOT EXISTS idx_alerts_history_archived_date ON alerts_history(archived_date);