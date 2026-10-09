# Matrice de risques CID — INC-2026-0302

**Classification** : TLP:AMBER · **Version** : 1.0 du 9 octobre 2026 · **Auteurs** : cellule CTI (Marc BOHOUSSOU, [Nom 2], [Nom 3])

## 1. Échelle

| Niveau | Confidentialité | Intégrité | Disponibilité |
|---|---|---|---|
| 1 Faible | Pas de donnée sensible exposée | Aucune modification | Aucune interruption |
| 2 Modéré | Données internes exposées, portée limitée | Modification localisée et réversible | Gêne de moins d'une journée |
| 3 Élevé | Données sensibles accessibles à l'attaquant | Système modifié par l'attaquant, confiance entamée | Arrêt d'un service pendant la remise en état |
| 4 Critique | Secrets ou données sensibles sortis de l'entreprise | Confiance perdue : reconstruction nécessaire | Arrêt étendu, ou capacité avérée de le provoquer |

La criticité d'un actif retient sa note la plus haute, relevée d'un cran lorsque l'actif conditionne la sécurité d'autres systèmes. Chaque note distingue ce qui est **prouvé** par un artefact de ce qui est **potentiel**.

## 2. Matrice par actif

| Actif | C | I | D | Criticité |
|---|---|---|---|---|
| `dc-01`, contrôleur de domaine | 4 | 4 | 3 | **Critique** |
| Comptes et secrets du domaine Active Directory | 4 | 3 | 2 | **Critique** |
| Données exfiltrées (2,3 Go, contenu inconnu) | 4 | 1 | 1 | **Critique** tant que le contenu n'est pas établi |
| `srv-fichiers-02`, serveur de fichiers | 3 | 3 | 2 | **Élevée** |
| `comptabilite-07`, poste de travail | 3 | 3 | 2 | **Élevée** |

## 3. Justification

### dc-01, contrôleur de domaine : critique

| Critère | Note | Prouvé | Potentiel |
|---|---|---|---|
| C | 4 | Lecture de la mémoire de LSASS (alerte 5). 2,3 Go sortis en clair depuis cet hôte (alerte 10) | Tous les identifiants du domaine sont à considérer comme connus de l'attaquant |
| I | 4 | Création puis suppression d'un compte (alerte 9), service créé puis supprimé (fiche BIN-03) | L'attaquant a pu créer d'autres accès non détectés. L'annuaire n'est plus digne de confiance |
| D | 3 | Aucune interruption observée | Depuis le contrôleur de domaine, un rançongiciel peut être diffusé à tout le parc. La remise en état imposera une coupure |

Le contrôleur de domaine délivre les accès de toute l'entreprise : sa compromission s'étend à tout ce qui s'y authentifie.

### Comptes et secrets du domaine : critique

L'attaquant a ouvert une session RDP sur le serveur de fichiers le 4 mars (alerte 7), **avant** de lire LSASS le 5 mars (alerte 5). Il disposait donc déjà d'identifiants valides, d'origine inconnue. La page de collecte d'identifiants (n°15, n°30, cote C2) est une explication possible, non prouvée. Les secrets sont compromis (C = 4) et rien ne garantit qu'ils n'ont pas été modifiés (I = 3).

### Données exfiltrées : critique par précaution

Le volume et la destination sont prouvés (alerte 10, indicateur n°24, cote B2). Le contenu ne l'est pas : le mémo du SOC indique ne pas connaître « l'étendue exacte des données exfiltrées ». Deux indices orientent : l'archive a été préparée sur `dc-01` (n°12, n°39), et le serveur de fichiers était accessible depuis la veille. La note reste à 4 tant que l'inventaire n'est pas fait, car elle conditionne les obligations de notification.

### srv-fichiers-02 : élevée

| Critère | Note | Prouvé | Potentiel |
|---|---|---|---|
| C | 3 | Session RDP illégitime (alerte 7), implant actif (alerte 8) | Lecture et copie des partages ; aucune alerte d'exfiltration depuis ce serveur |
| I | 3 | Code injecté dans `explorer.exe` (alerte 8, n°11). Implant encore actif le 6 mars (alerte 11) | Modification de fichiers partagés |
| D | 2 | Aucune interruption | Cible naturelle d'un chiffrement |

### comptabilite-07 : élevée

| Critère | Note | Prouvé | Potentiel |
|---|---|---|---|
| C | 3 | Balise transmettant nom de machine, utilisateur et privilèges (fiche BIN-02) | Accès aux documents comptables et aux identifiants de l'utilisateur |
| I | 3 | Deux persistances (n°36, n°38). Journal Sécurité effacé le 7 mars (alerte 12) : des preuves sont perdues | — |
| D | 2 | Aucune interruption | Le poste doit être réinstallé |

## 4. Scénarios de risque

| # | Scénario | Vraisemblance | Gravité | Niveau | Fondement |
|---|---|---|---|---|---|
| R1 | Publication ou revente des données exfiltrées, avec chantage | Probable | Critique | **Critique** | Exfiltration prouvée, mobile financier probable |
| R2 | Chiffrement du parc par rançongiciel depuis le domaine | Possible | Critique | **Élevé** | Capacité acquise (identifiants du domaine) ; aucun chiffrement observé |
| R3 | Retour de l'attaquant par les identifiants volés ou un accès resté en place | Probable | Élevée | **Élevé** | Activité constatée les 6 et 7 mars, après la détection |
| R4 | Rebond vers les systèmes industriels | Non observé | Critique | **À évaluer** | Aucun artefact ; dépend du cloisonnement entre bureautique et industriel |
| R5 | Manquement aux obligations de déclaration | Possible | Élevée | **Moyen** | Voir la note réglementaire |

## 5. Mesures de réduction

| Risque | Mesure | Échéance |
|---|---|---|
| R3 | Isoler `comptabilite-07` et `srv-fichiers-02`, après capture de la mémoire | Immédiat |
| R2, R3 | Renouveler tous les secrets du domaine, dont deux fois le compte `krbtgt`, et tous les comptes à privilèges | Sous 48 h |
| R3 | Rechercher sur tout le parc la tâche `MicrosoftEdgeUpdateTaskMachine`, la valeur `WinTelemetry` et le compte `svc-backup-temp` | Sous 48 h |
| R2 | Vérifier que les sauvegardes sont hors ligne, intègres et restaurables | Sous 48 h |
| R1 | Inventorier ce qui a pu sortir : contenu de `dc-01` et partages de `srv-fichiers-02` | Sous 72 h |
| R4 | Faire vérifier le cloisonnement entre le réseau bureautique et les systèmes industriels | Sous une semaine |
| Tous | Déployer les 15 règles Sigma et bloquer les indicateurs cotés A1 à B2 | Sous une semaine |
| R2, R3 | Protéger LSASS, interdire les macros venant d'Internet, réserver le RDP à un bastion, interdire la sortie Internet directe des contrôleurs de domaine | Sous un mois |

## 6. Limites

Les notes s'appuient sur trois actifs, les seuls cités par les artefacts. Rien ne prouve que d'autres machines ne sont pas touchées : le balayage du 3 mars (alerte 6) a visé tout le sous-réseau 10.20.0.0/16. La matrice doit être revue après la recherche de compromission sur l'ensemble du parc.
