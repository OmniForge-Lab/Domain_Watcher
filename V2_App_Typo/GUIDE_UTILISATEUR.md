# Guide Utilisateur - Système de Détection de Typosquatting

## Vue d'ensemble

Ce guide vous explique comment utiliser efficacement le système de détection de typosquatting avec le nouveau système de scoring et de gestion des alertes.

## Interface Principale

### Tableau de Bord

Le tableau de bord affiche :
- **Statistiques globales** : Nombre total d'alertes par statut
- **Alertes du jour** : Nouveaux domaines détectés aujourd'hui
- **Score de risque moyen** : Évaluation globale du niveau de menace
- **Actions recommandées** : Nombre d'alertes nécessitant une intervention

### Liste des Alertes

Chaque alerte affiche :
- **Domaine détecté** : Le domaine suspect identifié
- **Domaine original** : Le domaine légitime de référence
- **Score de risque** : Évaluation numérique (0-100) avec code couleur
- **Statut** : État actuel de l'alerte
- **Date de détection** : Quand le domaine a été identifié
- **Actions** : Boutons pour analyser et modifier le statut

## Système de Scoring

### Composants du Score (0-100)

Le score de risque est calculé en combinant plusieurs facteurs :

#### 1. Similarité (40% du score)
- **Très haute** (90-100) : Distance ≤ 1 caractère
- **Haute** (70-89) : Distance ≤ 2 caractères
- **Moyenne** (40-69) : Distance ≤ 3 caractères
- **Faible** (0-39) : Distance > 3 caractères

#### 2. Âge du Domaine (25% du score)
- **Très récent** (80-100) : < 30 jours
- **Récent** (50-79) : < 180 jours
- **Établi** (20-49) : < 1 an
- **Ancien** (0-19) : > 1 an

#### 3. Géolocalisation (15% du score)
- **Haut risque** (70-100) : Pays à risque élevé
- **Risque moyen** (40-69) : Pays à risque modéré
- **Faible risque** (0-39) : Pays sûrs

#### 4. Certificat SSL (10% du score)
- **Valide** (0-20) : Certificat SSL valide
- **Auto-signé** (40-60) : Certificat auto-signé
- **Expiré** (60-80) : Certificat expiré
- **Invalide** (70-90) : Certificat invalide
- **Absent** (80-100) : Pas de SSL

#### 5. Réputation (10% du score)
- **Propre** (0-10) : Aucune détection VirusTotal
- **Suspect** (30-50) : 1-2 détections
- **Malveillant** (80-100) : 3+ détections

### Niveaux de Risque

- **🟢 FAIBLE** (0-29) : Risque minimal, surveillance passive
- **🟡 MOYEN** (30-69) : Risque modéré, surveillance active
- **🔴 ÉLEVÉ** (70-100) : Risque élevé, action immédiate requise

## États des Alertes

### États Actifs (Surveillance Active)

#### 🟡 Nouveau
- **Description** : Domaine détecté récemment, analyse en cours
- **Durée max** : 7 jours
- **Action** : Transition automatique vers "Surveillance" si score < 30

#### 🔵 En Investigation
- **Description** : Analyse approfondie en cours
- **Durée max** : 30 jours
- **Action** : Analyse manuelle requise

#### ⚫ Surveillance
- **Description** : Domaine sous surveillance continue
- **Durée max** : 90 jours
- **Action** : Vérifications périodiques automatiques

### États d'Intervention (Action Requise)

#### 🔴 Action Requise
- **Description** : Intervention manuelle nécessaire
- **Durée max** : 1 jour
- **Action** : Traitement prioritaire obligatoire

#### 🔴 Escaladé
- **Description** : Escaladé vers l'équipe sécurité
- **Durée max** : 3 jours
- **Action** : Suivi par l'équipe sécurité

### États Passifs (Surveillance Réduite)

#### 🟢 Légitime
- **Description** : Domaine confirmé comme légitime
- **Action** : Archivage, surveillance minimale

#### ⚪ Parqué
- **Description** : Domaine parqué, risque faible
- **Durée max** : 180 jours
- **Action** : Vérification périodique d'expiration

#### ⚪ Expiré
- **Description** : Domaine expiré
- **Action** : Archivage automatique

### États Finaux (Archivés)

#### 🟢 Résolu
- **Description** : Problème résolu avec succès
- **Action** : Archivé définitivement

#### ⚫ Faux Positif
- **Description** : Alerte confirmée comme fausse
- **Action** : Utilisé pour améliorer la détection

#### ⚫ Bloqué
- **Description** : Domaine bloqué avec succès
- **Action** : Archivé avec suivi du blocage

## Procédures d'Utilisation

### Analyse d'une Nouvelle Alerte

1. **Examiner le score de risque**
   - Score élevé (>70) : Traitement prioritaire
   - Score moyen (30-70) : Investigation approfondie
   - Score faible (<30) : Surveillance passive

2. **Vérifier les composants du score**
   - Similarité : Vérifier la ressemblance visuelle
   - Âge : Domaines récents = plus suspects
   - Géolocalisation : Vérifier le pays d'origine
   - SSL : Certificats invalides = suspect
   - Réputation : Détections antivirus

3. **Analyser le contenu du site**
   - Cliquer sur "Analyser" pour voir les détails
   - Vérifier WHOIS, DNS, SSL, géolocalisation
   - Examiner le contenu du site si accessible

4. **Prendre une décision**
   - **Légitime** : Site officiel ou partenaire
   - **Surveillance** : Suspect mais pas confirmé
   - **Action requise** : Menace confirmée
   - **Faux positif** : Erreur de détection

### Gestion des Alertes Prioritaires

#### Score > 70 (Action Immédiate)
1. Vérifier immédiatement le contenu
2. Contacter l'équipe juridique si phishing confirmé
3. Documenter les preuves
4. Initier les procédures de blocage
5. Mettre à jour le statut vers "Escaladé" ou "Résolu"

#### Score 30-70 (Investigation)
1. Programmer une analyse dans les 24h
2. Vérifier l'évolution du site
3. Rechercher des indicateurs de compromission
4. Mettre à jour le statut selon les résultats

#### Score < 30 (Surveillance)
1. Programmer une vérification hebdomadaire
2. Surveiller les changements de contenu
3. Transition automatique vers "Légitime" après 90 jours sans activité suspecte

## Fonctionnalités Avancées

### Calcul de Score Manuel
- Utiliser le bouton "Calculer Score" pour recalculer
- Utile après des changements sur le domaine cible
- Met à jour automatiquement la base de données

### Filtres et Recherche
- **Par statut** : Filtrer les alertes par état
- **Par score** : Afficher seulement les scores élevés
- **Par date** : Alertes d'une période spécifique
- **Par domaine** : Recherche textuelle

### Exports et Rapports
- Export CSV des alertes
- Rapports de synthèse hebdomadaires
- Statistiques de performance

## Bonnes Pratiques

### Gestion Quotidienne
1. **Matin** : Vérifier les nouvelles alertes de la nuit
2. **Midi** : Traiter les alertes "Action requise"
3. **Soir** : Mettre à jour les statuts en cours

### Escalade
- Score > 80 : Escalade immédiate
- Phishing confirmé : Contact équipe juridique
- Domaine actif malveillant : Blocage d'urgence

### Documentation
- Toujours documenter les décisions
- Conserver les preuves (captures d'écran)
- Mettre à jour les commentaires d'alerte

## Dépannage

### Problèmes Courants

#### Score non calculé
- Vérifier la connectivité aux APIs externes
- Relancer le calcul manuellement
- Vérifier les logs d'erreur

#### Données manquantes
- WHOIS indisponible : Normal pour certains TLD
- SSL non vérifié : Domaine peut-être inactif
- Géolocalisation inconnue : IP non résolue

#### Faux positifs fréquents
- Ajuster les seuils de similarité
- Exclure les domaines légitimes connus
- Améliorer la liste des pays à faible risque

### Support

Pour toute question ou problème :
1. Consulter les logs de l'application
2. Vérifier la documentation technique
3. Contacter l'équipe de développement

## Mises à Jour

Ce guide sera mis à jour régulièrement. Vérifiez la version et la date de dernière modification.

**Version** : 1.0  
**Dernière mise à jour** : [Date actuelle]  
**Prochaine révision** : [Date + 3 mois]