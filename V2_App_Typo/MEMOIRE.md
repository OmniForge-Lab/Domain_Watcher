# PLAN DÉTAILLÉ DU MÉMOIRE D'ALTERNANCE
---

**Titre provisoire :** Conception et industrialisation d'une solution de détection et de scoring des risques de Typosquatting pour la protection de marque E-commerce.

---

## 1. Mise en contexte

### 1.1 Présentation de l’entreprise : Showroomprivé
**Showroomprivé** est un acteur majeur du **E-commerce (Pure Player)** en Europe, spécialisé dans la vente événementielle en ligne. Avec un modèle économique fondé exclusivement sur sa présence web et mobile, la confiance des membres est un actif stratégique critique. L'entreprise génère un chiffre d'affaires annuel significatif (plus de 600 millions d'euros) et traite des millions de transactions chaque année. Dans ce contexte, toute tentative d'usurpation d'identité, comme le typosquatting ou le phishing, ne menace pas seulement le chiffre d'affaires immédiat, mais érode durablement l'image de marque et la crédibilité auprès des clients.

### 1.2 Présentation du rôle de l’alternant et de l’organisation
Au sein de la Direction de la Cybersécurité, j'ai intégré une **équipe agile** fonctionnant par cycles de Sprints. Mon positionnement est transverse, me permettant d'intervenir sur plusieurs piliers de la sécurité :
*   **Blue Team :** Pour la surveillance active et le développement d'outils de détection.
*   **GRC (Gouvernance, Risques, Conformité) :** Pour l'alignement des outils techniques avec les risques métiers et les besoins juridiques.
*   **Red Team :** Pour tester la robustesse des règles de détection via des simulations d'attaques.
Au quotidien, je participe activement aux rituels agiles et assure le rôle de référent technique sur le projet "Domain Watcher".

## 2. Introduction du projet

### 2.1 Contexte d’émergence du projet
Le projet est né d'un constat alarmant au sein de **Showroomprivé** : la dépendance de l'entreprise à son canal web est totale, pourtant le risque de **Typosquatting** (enregistrement de noms de domaine visuellement proches pour tromper l'utilisateur) n'était pas traité de manière proactive. Jusqu'alors, la détection se faisait "au fil de l'eau", souvent suite à des signalements clients ou des retours du service client. La recrudescence observée des attaques de phishing ciblant la marque et usurpant son identité visuelle a agi comme un déclencheur majeur, rendant impérative l'industrialisation de la détection pour protéger le business et la confiance des membres.

### 2.2 Objectifs du projet et impact visé
L'objectif principal est de passer d'une posture purement réactive à une défense proactive et outillée. Le projet vise plusieurs impacts stratégiques :
*   **Priorisation intelligente (Risk Scoring) :** L'enjeu n'est plus seulement de tout détecter, mais de trier efficacement. Le système doit automatiquement qualifier le danger pour ne pas noyer les analystes SOC sous un volume ingérable d'alertes.
*   **Centralisation et Gouvernance :** Le développement d'un **Dashboard unique** centralise la gestion des incidents, offrant une vue d'ensemble en temps réel de la menace sur la marque.
*   **Automatisation opérationnelle :** Afin de libérer du temps pour des tâches à plus haute valeur ajoutée, les processus répétitifs d'analyse WHOIS, DNS et SSL sont délégués à des tâches planifiées.
*   **Support Juridique :** L'outil doit fournir des preuves techniques tangibles et structurées pour accélérer les procédures de "Takedown" (fermeture de sites malveillants).

### 2.3 État de l’art et stratégie "Make vs Buy"
Une analyse approfondie du marché a été menée pour identifier les solutions de protection de marque (Digital Risk Protection Services - DRPS). Le marché se divise en deux catégories :

1.  **Solutions SaaS Premium (PhishLabs, Bolster, BrandShield) :** Très performantes, elles offrent une détection et un takedown automatisé. Cependant, leur coût est prohibitif (estimé entre 30k€ et 60k€/an par domaine surveillé) et leur moteur de scoring est souvent une "boîte noire" difficilement adaptable aux spécificités de Showroomprivé.
2.  **Outils Open-Source isolés (DNStwist, Certstream) :** Excellentes briques techniques pour la génération de domaines ou la surveillance des logs CT, mais elles manquent de persistance, d'interface et de logique métier globale.

**Justification du développement interne (Make) :**
Le choix stratégique du développement interne a été motivé par trois facteurs :
*   **Économique :** Le coût de développement (estimé à environ 20 jours-homme pour le MVP) est largement inférieur aux licences annuelles des solutions SaaS.
*   **Personnalisation :** La nécessité d'un algorithme de scoring "maison" capable d'intégrer des critères spécifiques (ex: liste blanche de partenaires, géolocalisation spécifique).
*   **Souveraineté :** Garder la maîtrise totale des données de détection et de l'infrastructure de surveillance.

Le projet n'est donc pas une simple amélioration d'un PoC existant, mais la construction d'un écosystème complet transformant des briques élémentaires en une plateforme industrielle.

### 2.4 Descriptif rapide des grandes étapes du projet
Le projet s'est articulé autour de cinq phases majeures :
1.  **Conception :** Définition précise des règles métier de détection et des critères de risque.
2.  **Développement Backend :** Mise en place de l'architecture technique reposant sur **Python/FastAPI** et une base de données relationnelle.
3.  **Développement Core :** Implémentation des algorithmes de **Scoring** et des tâches de fond automatisées.
4.  **Développement Frontend :** Création de l'interface utilisateur pour permettre à l'équipe d'interagir avec les données.
5.  **Déploiement :** Mise en production, recette et rédaction de la documentation technique et utilisateur.

### 2.5 Descriptif du rôle joué par l’alternant
J'ai assumé une responsabilité de type **"Full Stack"**, prenant en charge le projet de bout en bout.
Sur le volet **Développement**, j'ai conçu et codé l'ensemble de la solution (Python, SQL, HTML/JS).
Sur le volet **Opérations (Ops)**, j'ai assuré le déploiement et l'automatisation via des scripts dédiés.
Enfin, sur le volet **Fonctionnel**, j'ai joué le rôle d'interface avec les parties prenantes (juridique, management) pour traduire leurs besoins en règles techniques concrètes.

## 3. Description du projet
*(Cœur du mémoire - Focus sur les apports personnels)*

### 3.1 Synthèse des phases du projet
La réalisation technique s'est déroulée en quatre temps forts. La première phase a consisté à bâtir le socle de **Collecte et Stockage**, avec la création de la base PostgreSQL et des scripts d'ingestion. La seconde phase, **Analyse et Enrichissement**, a permis de connecter l'outil aux serveurs WHOIS et DNS pour qualifier automatiquement les menaces. La troisième phase a vu la naissance du **Moteur de Décision**, véritable cerveau du système capable de scorer le risque. Enfin, la phase d'**Interface et Reporting** a rendu ces données exploitables visuellement pour l'équipe SOC.

### 3.2 Focus Technique 1 : Récupération et analyse des alertes
L'un des défis majeurs a été de surveiller des milliers de variations de domaines sans exploser les coûts d'API ni les quotas.
Pour y répondre, j'ai conçu un mécanisme intelligent de **cache local** et d'optimisation des requêtes. J'ai développé des scripts robustes capables de gérer les erreurs réseaux et de respecter scrupuleusement les limites de débit (Rate Limiting) des serveurs WHOIS publics, garantissant ainsi la pérennité et la discrétion de la surveillance.

### 3.3 Focus Technique 2 : Le Moteur de Scoring de Risque
Le cœur de la valeur ajoutée du projet réside dans sa capacité à distinguer un site inoffensif (ex: un domaine "à vendre") d'une menace réelle de phishing. Pour industrialiser cette intuition, j'ai modélisé et implémenté un **algorithme de scoring pondéré** (0 à 100) reposant sur cinq piliers techniques configurables :

1.  **Similarité visuelle (40%) :** Basée sur la distance de Levenshtein. Un domaine comme `sh0wroomprive.com` (distance 1) reçoit un score de 100 sur ce critère, tandis qu'une variation plus éloignée sera moins pénalisée.
2.  **Âge du domaine (25%) :** Les domaines créés il y a moins de 30 jours sont statistiquement plus dangereux. Ce critère pénalise fortement la "jeunesse" du domaine (score de 100 si < 30 jours).
3.  **Géolocalisation (15%) :** L'hébergement dans des zones géographiques à haut risque (ex: CN, RU, KP) augmente le score de suspicion.
4.  **Certificat SSL (10%) :** L'absence de certificat ou un certificat auto-signé est un signal fort de malveillance pour un site e-commerce.
5.  **Réputation (10%) :** Intégration de l'API VirusTotal pour vérifier si le domaine est déjà blacklisté par d'autres moteurs de sécurité.

**Logique de décision et Seuils :**
Le système catégorise les alertes selon trois seuils critiques définis avec les équipes métier :
*   **Risque Faible (< 30) :** Surveillance passive. Exemple : `showroomprive-blog.fr` (domaine ancien, SSL valide, hébergé en France).
*   **Risque Moyen (30-70) :** Alerte modérée, nécessite une levée de doute.
*   **Risque Élevé (> 70) :** Action immédiate requise. Exemple : `showroom-prive-login.com` détecté via Certstream, créé il y a 2 heures, sans SSL, hébergé dans une zone atypique. Ce type de domaine déclenche une notification prioritaire sur Teams.

Cette approche mathématique permet de transformer un flux brut de milliers de domaines en une liste priorisée de quelques alertes critiques par jour.

### 3.4 Focus Technique 3 : Interface utilisateur et Gestion du cycle de vie
Pour rendre ces données exploitables, j'ai développé un **Dashboard centralisé** complet. Loin d'être un simple tableau d'affichage, cette interface offre des fonctionnalités avancées de filtrage (par score, par date, par état) et d'action. Elle permet aux analystes de visualiser instantanément les menaces prioritaires.

En parallèle, pour éviter le phénomène de fatigue ("Alert Fatigue"), j'ai mis en place une gestion rigoureuse du cycle de vie des alertes. J'ai développé une **machine à états (State Machine)** qui automatise les transitions : une alerte naît à l'état "Nouveau", peut passer automatiquement en "Investigation" si son score évolue, ou être classée "Résolue" sans intervention humaine si la menace disparaît. Ce dynamisme est assuré par des tâches planifiées (Cron) qui nettoient et mettent à jour la base chaque nuit.
Enfin, l'outil ne reste pas passif : j'ai intégré un module de notification multicanal (via **Microsoft Teams**) utilisant des **Adaptive Cards**. Cela permet de pousser l'information critique directement vers les analystes avec un contexte riche, réduisant drastiquement le temps de réaction (MTTR).

### 3.5 Focus Technique 4 : Architecture et Performance
Au-delà des fonctionnalités visibles, j'ai soigné la qualité structurelle du code ("Software Craftsmanship") :
*   **Modularité (FastAPI APIRouter)** : L'application n'est pas monolithique mais découpée en modules logiques (ex: `routes/domain_info.py`), facilitant la maintenance et les tests unitaires.
*   **Intelligence en Base de Données** : Plutôt que de surcharger le serveur Python avec des calculs statistiques, j'ai délégué l'agrégation des données directement au moteur PostgreSQL via des **Vues SQL** (`scoring_statistics`). Cela garantit l'affichage instantané des métriques du Dashboard, quel que soit le volume de données.
*   **Résilience** : Le chargement de la configuration intègre des mécanismes de **Fallback** (recherche de variables d'environnement dans plusieurs chemins) pour garantir le démarrage de l'application même dans des environnements contraints ou mal configurés.

## 4. Gestion du projet

### 4.1 Méthodes et outils utilisés
Le projet a été piloté selon une approche **Agile/Scrum**, adaptée à la taille réduite de l'équipe et à l'incertitude technique liée au sujet. Nous avons utilisé un **tableau Kanban** pour visualiser le flux de travail et gérer les priorités en temps réel.

Sur le plan technique, l'industrialisation a été au cœur de la démarche :
*   **Stack Technique :** Python 3.12 (asynchronisme), FastAPI (performance API), PostgreSQL (gestion de données relationnelles).
*   **Déploiement Continu :** Développement de scripts de déploiement intelligents (`deploy_improvements.py`) incluant des phases d'auto-diagnostic pour minimiser les interruptions de service.
*   **Qualité logicielle :** Utilisation de verrous logiques (Thread-Safety) pour la gestion de la configuration et de pools de connexions pour optimiser les performances multi-utilisateurs.

### 4.2 Planification et adaptation aux aléas
Initialement, le projet suivait un planning linéaire (Gantt prévisionnel) sur six mois. Cependant, la réalité du terrain a imposé une gestion par **scope variable**. Les départs de collaborateurs mentionnés précédemment ont nécessité de recentrer les efforts sur le "Core Engine" (Scoring et Dashboard) au détriment de fonctionnalités secondaires. Cette agilité a permis de livrer un outil opérationnel dans les délais impartis, malgré une réduction de 30% de la capacité de production de l'équipe sur le dernier trimestre.

### 4.3 Organisation et Responsabilités (RACI)
Pour clarifier les rôles au sein de cette organisation mouvante, deux matrices RACI ont été définies :

**Tableau 1 : RACI Projet (Phase de Construction)**

| Tâche | Alternant (Moi) | Tuteur / Manager | Dev Senior | Juridique |
| :--- | :---: | :---: | :---: | :---: |
| **Conception / Choix Archi** | **R** | A | C | I |
| **Développement Backend** | **R** | I | C | - |
| **Validation Règles Métier** | C | **A** | I | C |
| **Recette / Tests** | **R** | C | C | - |
| **Mise en Production** | **R** | A | I | - |

**Tableau 2 : RACI Opérationnel (Phase d'Exploitation)**

| Action | Analyste SOC | Manager Cyber | Alternant (Moi) | Juridique |
| :--- | :---: | :---: | :---: | :---: |
| **Tri des alertes (Dashboard)** | **R** | A | C (Support) | - |
| **Investigation approfondie** | **R** | I | C | - |
| **Décision de Takedown** | C | **A** | I | **R** |
| **Maintenance de l'outil** | I | A | **R** | - |

*Légende : **R** = Réalise, **A** = Approuve/Responsable, **C** = Consulté, **I** = Informé*

## 5. Présentation des résultats du projet

### 5.1 Atteinte des objectifs et impact business
Les résultats sont probants : l'interface est aujourd'hui le point d'entrée quotidien de l'équipe SOC pour la protection de marque. 
*   **Efficacité :** Le temps moyen de détection (MTTD) d'un nouveau domaine suspect est passé de plusieurs jours (via signalements) à quelques minutes (via Certstream).
*   **Précision :** L'algorithme de scoring permet d'éliminer automatiquement 85% du bruit (domaines légitimes ou inoffensifs), concentrant l'effort humain sur les menaces réelles.
*   **Économie :** En développant cette solution en interne, Showroomprivé a évité un investissement SaaS annuel conséquent tout en disposant d'un outil parfaitement aligné sur ses processus de Takedown.

### 5.2 Impacts non prévus et gestion de la donnée
Au-delà de la détection, le projet a permis de cartographier précisément le patrimoine numérique de l'entreprise. Un effet de bord positif a été l'identification et le "Whitelisting" de domaines légitimes qui n'étaient plus répertoriés.
Sur le plan technique, la gestion des doublons a été un défi majeur. J'ai dû implémenter une logique de déduplication rigoureuse au niveau SQL pour garantir l'intégrité des rapports statistiques, évitant ainsi de fausser les indicateurs de performance (KPI) présentés à la direction.

## 6. Analyse critique du projet

### 6.1 Bilan des réussites et gestion des aléas
L'architecture découplée (séparation nette entre l'API Backend et le Frontend) est un franc succès, facilitant les évolutions du moteur sans impacter l'interface. La mise en place du scoring a radicalement changé la perception de la menace typosquatting au sein du SOC.

Cependant, le projet a dû faire face à des défis organisationnels majeurs, notamment le **départ de deux collaborateurs clés** durant la phase de développement. Dans une petite équipe de trois personnes, cette perte de capital humain a eu un impact direct :
*   **Réduction du périmètre (Scope) :** Certaines fonctionnalités avancées, comme l'analyse par Computer Vision (comparaison de logos), ont dû être reportées pour garantir la livraison du socle de détection et de scoring.
*   **Gestion de la dette technique :** Le besoin de maintenir une cadence de livraison malgré les effectifs réduits a parfois conduit à privilégier la fonctionnalité immédiate sur l'optimisation à long terme, une dette que j'ai dû apurer en fin de projet via des phases de refactoring.
*   **Résilience organisationnelle :** Cette expérience a souligné l'importance de la documentation et du partage de connaissances (Pair Programming, Wiki technique) pour éviter les silos de compétences ("Bus Factor").

### 6.2 Limites techniques et objectifs non atteints
Malgré les succès, des limites subsistent. La gestion des **faux positifs persistants**, notamment les domaines "Parked" (pages de parking), reste complexe. Ces cas nécessitent encore souvent une vérification humaine, car l'algorithme peine à distinguer automatiquement une page de parking publicitaire d'une page de phishing sophistiquée sans analyse visuelle.

L'objectif d'automatisation totale du "Takedown" n'a pas non plus été atteint. Si l'outil fournit toutes les preuves nécessaires, la décision finale de suppression reste humaine et juridique. Cette prudence est nécessaire pour éviter de couper par erreur des domaines partenaires ou légitimes (risques de "collateral damage").

### 6.3 Analyse de l’apport personnel
Ce projet a été un accélérateur de compétences. Sur le plan **technique**, j'ai acquis une maîtrise avancée de l'architecture logicielle (FastAPI) et de l'optimisation de bases de données. Sur le plan **métier**, j'ai développé ma capacité à appréhender un enjeu juridique complexe (la protection de marque) pour le traduire en une solution technique concrète et opérationnelle.

## 7. Apprentissage personnel
Cette expérience a solidifié mes compétences techniques sur l'écosystème Python asynchrone et les protocoles bas niveau (DNS/WHOIS).
Au-delà du code, j'ai progressé sur des compétences transverses essentielles : la rigueur documentaire, la gestion de la dette technique, et la compréhension fine des mécanismes légaux liés à la propriété intellectuelle sur Internet.

## 8. Conclusion
En conclusion, ce projet a permis de transformer une activité de surveillance initialement artisanale, chronophage et réactive en une véritable capacité de défense **proactive, structurée et outillée**. Il dote l'entreprise d'un atout durable face aux menaces de typosquatting, adapté aux enjeux d'un grand acteur du e-commerce.

## 9. Remerciements
