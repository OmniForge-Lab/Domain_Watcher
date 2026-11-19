-- Créer les tables nécessaires pour le projet de détection de typosquatting

-- 1. Table des domaines surveillés
CREATE TABLE IF NOT EXISTS watched_domains (
    id SERIAL PRIMARY KEY,
    domain TEXT UNIQUE NOT NULL,
    distance_threshold INTEGER DEFAULT 1,
    active BOOLEAN DEFAULT TRUE
);

-- 2. Table des alertes générées par dnstwist ou certstream
CREATE TABLE IF NOT EXISTS alerts (
    id SERIAL PRIMARY KEY,
    source TEXT,
    watched_domain_id INTEGER REFERENCES watched_domains(id),
    detected_domain TEXT NOT NULL,
    lev_distance INTEGER,
    dns_a TEXT,
    dns_mx TEXT,
    dns_ns TEXT,
    whois_created TEXT,
    whois_registrar TEXT,
    issuer TEXT,
    email TEXT,
    detection_date TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    status TEXT DEFAULT 'new',
    comment TEXT,
    screenshot_path TEXT
);

