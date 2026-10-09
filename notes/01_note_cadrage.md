# Note de cadrage — Investigation CTI Helios Energy

**Référence** : INC-2026-0302 · **Classification** : TLP:AMBER · **Version** : 1.0, fin de J1
**Équipe** : [Nom 1], [Nom 2], [Nom 3] · **Commanditaire** : direction et responsable SOC d'Helios Energy

## 1. Commande

Helios Energy, opérateur d'importance vitale, a subi une intrusion détectée le 2 mars 2026. Le SOC nous remet 40 indicateurs, 12 alertes SIEM, 3 fiches d'analyse de binaires et un mémo. Nous devons répondre à quatre questions : que s'est-il passé, qui en est l'auteur probable, quel est l'impact, et comment détecter un retour de l'attaquant.

## 2. Périmètre

**Dans le périmètre**
- Les trois actifs cités par les artefacts : `comptabilite-07`, `srv-fichiers-02`, `dc-01`.
- La période du 2 au 7 mars 2026.
- L'infrastructure et l'outillage de l'attaquant visibles dans le dossier.
- L'attribution à un groupe ou à un cluster, avec niveau de confiance.

**Hors périmètre**
- Toute recherche d'information sur la victime en sources ouvertes.
- L'exécution des binaires : seules les fiches d'analyse sont exploitées.
- Toute interaction ou achat sur le dark web : consultation et capture uniquement, horodatées.
- La remédiation opérationnelle : nous formulons des recommandations, nous n'intervenons pas sur le SI.
- Le volet optionnel de validation des règles sous Wazuh, non retenu par l'équipe.

## 3. Hypothèses de départ

Ce sont des hypothèses à éprouver, pas des conclusions. Chacune sera confirmée ou écartée à partir des artefacts.

| # | Hypothèse | Ce qui la motive | Ce qui la mettrait en défaut |
|---|---|---|---|
| H1 | Un seul acteur est à l'origine de toute la chaîne | Chaîne « build 7.3 » commune à BIN-01 et BIN-02 | Outils ou infrastructures sans lien entre les phases |
| H2 | Acteur cybercriminel à motivation financière, outillage proche de la famille FIN7/Carbanak | Format de balise et gigue de 20 % (fiche BIN-02) | Absence d'autres recoupements que ce seul indice |
| H3 | Acteur étatique visant un opérateur d'énergie | Nature de la victime uniquement | Aucun artefact technique ne l'appuie |
| H4 | Objectif : vol de données, avec extorsion ou rançongiciel possible | Vol d'identifiants, exfiltration de 2,3 Go, effacement de journaux | Aucun chiffrement observé à ce stade |
| H5 | L'attaquant est encore présent | Activité sur deux hôtes les 6 et 7 mars | Preuve d'un confinement effectif |

H3 est conservée comme hypothèse concurrente pour limiter le biais de confirmation.

## 4. Sources envisagées

| Source | Usage | Cote a priori |
|---|---|---|
| Fiches d'analyse des binaires | Comportements, techniques, liens entre outils | A |
| Alertes SIEM | Chronologie, hôtes touchés | A à B |
| Indicateurs du SOC | Infrastructure, corrélation | Cote fournie, de A1 à D4 |
| Mémo du SOC | Contexte ; daté du 2 mars mais décrit le 5 | B |
| MITRE ATT&CK (techniques, groupes, logiciels) | Nommer les techniques, comparer aux groupes connus | A |
| Galaxies MISP, publications ANSSI/CERT-FR et éditeurs | Recoupement des modes opératoires | B |
| Démonstration publique d'OpenCTI | Comprendre le modèle de données | Découverte seulement |

Règle de travail : une technique n'est retenue que si elle renvoie à un artefact identifié (alerte, indicateur ou fiche). Un rapport public sert à comparer, jamais à compléter.

## 5. Démarche et planning

| Jour | Objectif | Livrables | Pilote |
|---|---|---|---|
| J1 | Cadrage, triage des artefacts, MISP opérationnel | Note de cadrage, tableau de triage, chronologie v0 | Tous |
| J2 | Chargement et corrélation dans MISP | Événement MISP complet : objets, relations, tags TLP et Admiralty | [Nom 1] |
| J3 | Chaîne d'attaque et attribution | Cartographie ATT&CK, Diamond Model, note d'attribution v1 | [Nom 2], [Nom 3] |
| J4 | Rédaction | Rapport tactique et 10 règles Sigma, rapport stratégique, matrice CID | [Nom 2], [Nom 3] |
| J5 | Finalisation | Bundle STIX 2.1, graphe, notes ANSSI et partage, soutenance | Tous |

## 6. Répartition

| Rôle | Responsable | Livrables portés |
|---|---|---|
| Renseignement structuré | [Nom 1] | Événement MISP, bundle STIX 2.1, graphe, note de partage TLP |
| Analyse et détection | [Nom 2] | Chaîne d'attaque, ATT&CK et Diamond Model, 10 règles Sigma, rapport tactique |
| Attribution et restitution | [Nom 3] | Note d'attribution, matrice CID, rapport stratégique, note ANSSI |

Chaque livrable est relu par un autre membre avant dépôt. Le dépôt Git `cti-helios-energy` fait foi ; un point d'équipe de 15 minutes ouvre et clôt chaque journée. La soutenance est préparée et portée à trois.

## 7. Points à arbitrer avec le commanditaire

1. Les étiquettes IP-07, IP-08 et IP-09 des fiches ne correspondent pas à l'ordre du fichier d'indicateurs : quelle correspondance retenir ?
2. Le poste `comptabilite-07` a-t-il été isolé ? Il est encore actif le 7 mars.
3. D'autres salariés ont-ils reçu le leurre imitant le portail RH ?
4. Que contenaient les serveurs de fichiers et quelles données transitent par `dc-01` ? L'évaluation de l'impact en dépend.
