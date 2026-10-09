# CTI Helios Energy — INC-2026-0302

Investigation de renseignement sur les menaces menée à partir du dossier d'artefacts du SOC d'Helios Energy (entreprise fictive, opérateur d'importance vitale). Classification de l'ensemble : **TLP:AMBER**.

Équipe : Marc BOHOUSSOU, [Nom 2], [Nom 3].

## Livrables

| Livrable du sujet | Fichier |
|---|---|
| Note de cadrage | `notes/01_note_cadrage.md` |
| Rapport stratégique (direction) | `rapports/rapport_strategique_direction.pdf` |
| Rapport tactique (SOC) et règles Sigma | `rapports/rapport_tactique_SOC.pdf`, `sigma/` |
| Bundle STIX 2.1 | `stix/bundle_helios.json` |
| Graphe du renseignement | `graphe/graphe_helios.png` |
| Note d'attribution | `notes/04_note_attribution.md` |
| Matrice de risques CID | `notes/05_matrice_risques_CID.md` |
| Note réglementaire ANSSI | `notes/06_note_ANSSI.pdf` |
| Note de partage communautaire | `notes/07_note_partage_TLP.pdf` |

Documents de travail : `notes/02_triage_iocs.md` (triage des 40 indicateurs), `notes/03_chaine_attaque.md` (chronologie et techniques ATT&CK).

## Reproduire le bundle et le graphe

```
pip install misp-stix stix2 networkx matplotlib
python stix/convertir_misp_en_stix.py stix/misp_event_helios.json stix/misp_export_stix2.json
python stix/enrichir_bundle.py stix/misp_export_stix2.json stix/bundle_helios.json
python graphe/generer_graphe.py stix/bundle_helios.json graphe/graphe_helios.png
```

| Fichier | Rôle |
|---|---|
| `stix/misp_event_helios.json` | Sauvegarde de l'événement MISP (export « MISP JSON ») |
| `stix/misp_export_stix2.json` | Conversion STIX 2.1 par `misp-stix`, le convertisseur officiel de MISP |
| `stix/bundle_helios.json` | **Bundle final** : export MISP enrichi du cluster HELIOS-C1, des trois outils, des liens vers les techniques ATT&CK et de la source de chaque objet |

L'export « STIX 2 » de l'interface MISP renvoyait une erreur interne sur notre instance : la conversion est faite avec la même bibliothèque, en ligne de commande. Chaque ajout du script d'enrichissement cite l'artefact qui le fonde.

## Valider les règles Sigma

```
pip install sigma-cli pysigma-backend-splunk
sigma check sigma/
```

## Conclusion en une phrase

Cluster cybercriminel non nommé (HELIOS-C1), recouvrement partiel d'outillage avec la famille Carbanak/FIN7, confiance moyenne (cote Admiralty B3) ; aucun artefact ne soutient l'hypothèse d'un acteur étatique.
