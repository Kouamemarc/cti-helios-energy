# Règles Sigma — INC-2026-0302

15 règles, chacune rattachée à un artefact du dossier. Les 12 alertes SIEM sont couvertes.

| # | Fichier | Détecte | Source de journaux | ATT&CK | Artefact | Niveau |
|---|---|---|---|---|---|---|
| 01 | `01_office_lance_powershell_encode` | Application Office qui lance PowerShell encodé ou masqué | Création de processus | T1059.001, T1204.002 | Alerte 1, BIN-01 | Élevé |
| 02 | `02_proxy_telechargement_executable_domaines_campagne` | Exécutable téléchargé depuis un domaine de la campagne | Proxy | T1105 | Alerte 2 | Élevé |
| 03 | `03_tache_planifiee_imitant_edge_update` | Tâche planifiée imitant Edge Update, créée par schtasks | Création de processus | T1053.005, T1036.004 | Alerte 3, n°36 | Élevé |
| 04 | `04_registre_run_wintelemetry` | Valeur Run `WinTelemetry` | Registre | T1547.001 | n°38, BIN-01 | Élevé |
| 05 | `05_dns_domaines_campagne` | Résolution d'un domaine de la campagne | DNS | T1071.001, T1008 | Alertes 4 et 11 | Élevé |
| 06 | `06_explorer_parent_inhabituel` | `explorer.exe` lancé par un parent inhabituel | Création de processus | T1055.012 | Alerte 8, BIN-02 | Moyen |
| 07 | `07_rdp_serveur_source_non_autorisee` | Session RDP sur un serveur hors réseau d'administration | Journal Sécurité (4624) | T1021.001 | Alerte 7 | Moyen |
| 08 | `08_acces_memoire_lsass` | Lecture de la mémoire de LSASS | Accès processus (Sysmon 10) | T1003.001 | Alerte 5, BIN-03 | Critique |
| 09 | `09_compte_svc_backup_temp` | Création ou suppression de `svc-backup-temp` | Journal Sécurité (4720, 4726) | T1136.002 | Alerte 9, n°37 | Élevé |
| 10 | `10_parefeu_ip_commande_exfiltration` | Connexion vers une adresse de commande ou d'exfiltration | Pare-feu | T1071.001, T1048.003 | Alertes 4 et 10 | Critique |
| 11 | `11_effacement_journal_securite_wevtutil` | Effacement de journal avec wevtutil | Création de processus | T1685.005 (ex-T1070.001) | Alerte 12 | Élevé |
| 12 | `12_fichiers_outils_et_collecte` | Dépôt des outils ou du fichier de collecte | Création de fichier | T1074.001, T1105 | n°4, 7, 39 | Élevé |
| 13 | `13_compte_cree_puis_supprime_correlation` | Tout compte créé puis supprimé en moins d'une heure | Journal Sécurité, corrélation | T1136.002 | Alerte 9 | Élevé |
| 14 | `14_empreintes_binaires_campagne` | Exécution de BIN-02 ou BIN-03 par empreinte | Création de processus | T1204.002 | n°4, 7 | Critique |
| 15 | `15_balayage_interne_smb_rdp_correlation` | Une source contacte 30 hôtes ou plus sur 445/3389 en 5 min | Pare-feu, corrélation | T1046 | Alerte 6 | Moyen |

## Deux familles de règles

- **Comportementales (01, 03, 06, 07, 08, 11, 13, 15)** : elles restent valables si l'attaquant change d'infrastructure ou recompile ses outils. Ce sont les plus durables.
- **Fondées sur des indicateurs (02, 04, 05, 09, 10, 12, 14)** : très peu de faux positifs, mais contournées dès que l'attaquant change un nom ou une adresse. Seuls les indicateurs cotés A1 à B2 y figurent, plus les domaines d'hameçonnage.

## Validation effectuée

```
pip install sigma-cli pysigma-backend-splunk pysigma-backend-elasticsearch
sigma check sigma/
sigma convert -t splunk -p sysmon -p splunk_windows sigma/01_office_lance_powershell_encode.yml
```

- `sigma check` : 0 erreur, 0 erreur de condition, 0 problème sur les 15 fichiers (sigma-cli 3.1.0, étiquettes vérifiées contre ATT&CK v19.2 ; le contrôle des étiquettes D3FEND n'a pas pu tourner dans l'environnement de test, à relancer en local).
- Conversion Splunk réussie pour 14 règles : résultat dans `_conversion_splunk.spl`.
- Règle 13 (corrélation ordonnée dans le temps) : seul le moteur EQL d'Elastic la convertit. Sur un autre SIEM, utiliser la règle 09 ou écrire la corrélation à la main.

## Limites à connaître

- **Aucune règle n'a été rejouée sur des journaux.** La validation est syntaxique. Le test sur les journaux bruts relève du volet optionnel Wazuh, non retenu.
- Les règles 01, 03, 04, 06, 08, 11, 12 et 14 supposent Sysmon ou un EDR qui journalise la création de processus avec la ligne de commande.
- Règle 07 : la plage `10.20.99.0/24` est un exemple, à remplacer par le réseau d'administration réel. La condition « hors horaires » se règle dans la planification côté SIEM, Sigma ne filtre pas sur l'heure.
- Règle 06 : couverture indirecte de l'alerte 8. Elle repose sur l'hypothèse que le creux de processus passe par la création d'un `explorer.exe`.
- Règle 05 : le domaine `helios-energy-portal.test` identifie la victime. À retirer avant tout partage externe.
- La balise périodique (300 s, plus ou moins 20 %) ne s'exprime pas en Sigma : elle se chasse par une requête statistique sur les journaux du proxy.
