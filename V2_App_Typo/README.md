# Système de Détection de Typosquatting

## Vue d'ensemble

Ce projet est un système de détection et d'analyse de domaines suspects utilisant des techniques de typosquatting. Il combine plusieurs sources de données (DNSTwist, Certificate Transparency, APIs externes) pour identifier et analyser les domaines potentiellement malveillants.

## Architecture

### Composants principaux

1. **App_Typo** - Application web principale (FastAPI)
2. **certstream-server-go** - Serveur de surveillance Certificate Transparency
3. **dnstwist** - Générateur de variantes de domaines

### Technologies utilisées

- **Backend** : FastAPI (Python)
- **Frontend** : HTML/JavaScript/Bootstrap
- **Base de données** : PostgreSQL
- **Surveillance** : Certificate Transparency Logs
- **APIs externes** : WHOIS, VirusTotal, Géolocalisation

## Installation et Configuration

### Prérequis

- Python 3.11+
- PostgreSQL
- Go 1.19+ (pour certstream-server-go)

### Installation

```bash
# Cloner le repository
git clone <repository-url>
cd V2_App_Typo

# Installer les dépendances Python
pip install -r requirements.txt

# Configurer la base de données
psql -U postgres -f init_typoscan.sql

# Configurer les variables d'environnement
cp .env.example .env
# Éditer .env avec vos configurations
```

### Configuration de la base de données

```sql
-- Voir init_typoscan.sql pour la structure complète
CREATE TABLE watched_domains (
    id SERIAL PRIMARY KEY,
    domain VARCHAR(255) UNIQUE NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE alerts (
    id SERIAL PRIMARY KEY,
    watched_domain_id INTEGER REFERENCES watched_domains(id),
    detected_domain VARCHAR(255) NOT NULL,
    status VARCHAR(50) DEFAULT 'nouveau',
    risk_score INTEGER DEFAULT 0,
    detection_date TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);
```

## Utilisation

### Démarrage de l'application

```bash
# Démarrer l'application web
uvicorn main:app --reload

# Accéder à l'interface web
http://localhost:8000
```

### Changements UI (V2)

- Le bouton `🎯 SCORE RISQUE` a été retiré de la section `🛠️ Outils d'analyse`.
- La fonction `analyzeAll()` déclenche déjà `calculateGlobalRiskScore()` à la fin de la séquence d'analyses.
- Pour calculer le score manuellement, utilisez le bouton `🔍 ANALYSER TOUT` ou exécutez individuellement les outils puis le calcul global.

### API Endpoints

- `GET /` - Interface web principale
- `GET /alerts` - Liste des alertes
- `GET /whois?domain=<domain>` - Informations WHOIS
- `GET /dns?domain=<domain>` - Analyse DNS
- `GET /ssl?domain=<domain>` - Vérification SSL
- `GET /similarity?domain=<domain>` - Analyse de similarité
- `GET /geolocation?domain=<domain>` - Géolocalisation
- `GET /virus_total?domain=<domain>` - Analyse VirusTotal
- `POST /run_dnstwist` - Lancer l'analyse DNSTwist

## États des Alertes

### États actuels
- `nouveau` - Domaine détecté récemment
- `investigating` - En cours d'analyse
- `legitimate` - Confirmé comme légitime
- `suspicious` - Suspect, nécessite surveillance
- `malicious` - Confirmé malveillant
- `resolved` - Problème résolu
- `false_positive` - Fausse alerte

### Système de scoring

Le score de risque (0-100) est calculé en fonction de :
- Similarité avec le domaine original (40%)
- Âge du domaine (25%)
- Géolocalisation (15%)
- Certificat SSL (10%)
- Réputation VirusTotal (10%)

## Surveillance et Monitoring

### Logs

Les logs sont stockés dans la table `logs` et accessibles via `/logs`.

### Métriques

- Nombre d'alertes par statut
- Temps de réponse des APIs
- Taux de faux positifs

## Développement

### Structure du projet

```
App_Typo/
├── main.py              # Application FastAPI principale
├── templates/
│   ├── index.html       # Interface web
│   └── logs.html        # Page des logs
├── requirements.txt     # Dépendances Python
├── init_typoscan.sql   # Structure de la base de données
└── .env                # Variables d'environnement
```

### Contribution

1. Fork le projet
2. Créer une branche feature (`git checkout -b feature/nouvelle-fonctionnalite`)
3. Commit les changements (`git commit -am 'Ajouter nouvelle fonctionnalité'`)
4. Push vers la branche (`git push origin feature/nouvelle-fonctionnalite`)
5. Créer une Pull Request

## Roadmap

### Court terme (1-2 mois)
- [x] Documentation technique de base
- [ ] Révision des états d'alerte
- [ ] Système de scoring amélioré
- [ ] Tests unitaires

### Moyen terme (3-6 mois)
- [ ] Surveillance des changements de domaine
- [ ] Outils internes WHOIS
- [ ] Documentation utilisateur
- [ ] API de notification

### Long terme (6+ mois)
- [ ] Algorithmes de légitimité avancés
- [ ] Réduction de la dépendance aux APIs
- [ ] Système d'intervention automatisé
- [ ] Machine Learning pour la détection

## Support

Pour toute question ou problème :
1. Consulter cette documentation
2. Vérifier les logs de l'application
3. Contacter l'équipe de développement

## Licence

[Spécifier la licence du projet]