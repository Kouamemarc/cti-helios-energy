# Triage des 40 indicateurs — INC-2026-0302

Version de travail, J1. Source : `artefacts/iocs/02_indicateurs_40.csv`, cotes Admiralty fournies par le SOC.
Collecte : dossier remis par le SOC, valeurs conservées neutralisées (`[.]`, `hxxps`).

## 1. Règle de décision

| Classe | Cotes | Usage |
|---|---|---|
| Socle | A1 à B2 | Détection, blocage, preuve dans la chaîne d'attaque |
| À corroborer | B3 à C3 | Surveillance ; jamais seul appui d'une conclusion |
| Faible | C4 à D4 | Hypothèse de travail ; exclu de l'attribution |

## 2. Répartition

Par type : domain 6, host 5, ipv4 10, md5 3, sha1 3, sha1-cert 3, sha256 6, url 4.

Par cote : A1 7, A2 5, B2 14, B3 3, C2 3, C3 5, C4 2, D4 1.

Par classe : Socle 26, À corroborer 11, Faible 3.

## 3. Tableau de triage

| # | Type | Valeur | Contexte | Première vue (UTC) | Cote | Artefact lié | Classe | Remarque |
|---|---|---|---|---|---|---|---|---|
| 1 | sha256 | `2d10d13c3f3a045dc12a48e0a484018c053d0e83c607f2796fc9b8307c0d66e5` | BIN-01 facture_mars_2026.xlsm | 2026-03-02 08:30 | A1 | BIN-01, alerte 1 | Socle |  |
| 2 | sha1 | `4911bfb2fa8f76909de149299ef05e6b1455ea24` | BIN-01 facture_mars_2026.xlsm (SHA-1) | 2026-03-02 08:30 | A1 | BIN-01 | Socle |  |
| 3 | md5 | `8ba35251cca8daa4a05331bba8f95b05` | BIN-01 facture_mars_2026.xlsm (empreinte faible, pour antivirus hérités) | 2026-03-02 08:30 | A2 | BIN-01 | Socle | MD5 : détection seulement, pas une preuve |
| 4 | sha256 | `cdf03e90d85977619f7881a13f59a275812dbf0e4ae29874493728b0ef78ebc9` | BIN-02 svchost_update.exe | 2026-03-02 08:41 | A1 | BIN-02, alerte 2 | Socle |  |
| 5 | sha1 | `ca91f74f2438d710e130a5a413b2c75219c9d5a9` | BIN-02 svchost_update.exe (SHA-1) | 2026-03-02 08:41 | A1 | BIN-02 | Socle |  |
| 6 | md5 | `91678506a5474354f1ceb4c12c3c56dd` | BIN-02 svchost_update.exe (empreinte faible, pour antivirus hérités) | 2026-03-02 08:41 | A2 | BIN-02 | Socle | MD5 : détection seulement, pas une preuve |
| 7 | sha256 | `f4109cd2860816d568c5581edf8ed5df28d35471fa8ff849e9ee2451b69135f0` | BIN-03 rundll32_helper.dll | 2026-03-05 14:05 | A1 | BIN-03, alerte 5 | Socle |  |
| 8 | sha1 | `d1a4a3501bd1b1d9bc32ade2b4add3cb135e36b8` | BIN-03 rundll32_helper.dll (SHA-1) | 2026-03-05 14:05 | A1 | BIN-03 | Socle |  |
| 9 | md5 | `3435016f3f2aacce36b71abb636cfc64` | BIN-03 rundll32_helper.dll (empreinte faible, pour antivirus hérités) | 2026-03-05 14:05 | A2 | BIN-03 | Socle | MD5 : détection seulement, pas une preuve |
| 10 | sha256 | `81aa487933bb715f9dabd1755eff6cfd13a9c635e1b3bc4adff3ccbc78b8660f` | Charge PowerShell déchiffrée par BIN-01 (en mémoire) | 2026-03-02 08:32 | B2 | BIN-01, alerte 1 | Socle | Charge en mémoire : pas de fichier sur disque |
| 11 | sha256 | `8772b487de8ea8d30a7630e906afa95dcbf4a75f5915066f8b6a40d487201171` | Module injecté par BIN-02 dans explorer.exe | 2026-03-04 11:06 | B2 | BIN-02, alerte 8 | Socle | Vu sur srv-fichiers-02 : la balise a été propagée |
| 12 | sha256 | `a0e1f129a0155e96b0e04e8bc26b0d07fa8fb47c79f63a7e5a6227b27f239730` | Archive chiffrée préparée avant exfiltration (BIN-03) | 2026-03-05 14:45 | B2 | BIN-03, alerte 10 | Socle | Contenu de l'archive inconnu |
| 13 | domain | `cdn-svc-update[.]test` | Téléchargement de la charge BIN-02 | 2026-03-02 08:41 | B2 | BIN-01, alerte 2 | Socle | = D-01 des fiches |
| 14 | domain | `api-telemetry-eu[.]test` | Commande et contrôle de BIN-02 | 2026-03-02 09:15 | B2 | BIN-02, alerte 4 | Socle | = D-02 des fiches |
| 15 | domain | `mail-secure-login[.]test` | Page d'hameçonnage liée au courriel initial | 2026-03-02 07:58 | C2 | aucune alerte | À corroborer | Vue 32 min avant BIN-01 : second vecteur possible |
| 16 | domain | `static-assets-cache[.]test` | Second domaine de repli, même certificat | 2026-03-03 03:22 | C3 | alerte 11 | À corroborer | = D-04 ; relié au C2 par le certificat n°33 |
| 17 | domain | `helios-energy-portal[.]test` | Domaine d'usurpation imitant la victime | 2026-03-02 06:40 | B3 | aucune alerte | À corroborer | Imite la victime : indice de ciblage |
| 18 | domain | `update-win-msft[.]test` | Nom de tâche planifiée associé | 2026-03-04 11:04 | C3 | aucune alerte | À corroborer | Typé « domaine » mais décrit comme nom de tâche : ambigu |
| 19 | ipv4 | `198.51.100.23` | Résolution de cdn-svc-update[.]test | 2026-03-02 08:41 | B2 | alerte 2 (indirect) | Socle |  |
| 20 | ipv4 | `198.51.100.24` | Résolution de api-telemetry-eu[.]test | 2026-03-02 09:15 | B2 | alerte 4 (indirect) | Socle |  |
| 21 | ipv4 | `203.0.113.14` | Serveur de commande principal (BIN-02) | 2026-03-02 09:20 | B2 | BIN-02 | Socle | IP différente de la résolution n°20 : relais possible |
| 22 | ipv4 | `203.0.113.15` | Serveur de commande de repli | 2026-03-03 02:00 | C3 | aucune alerte | À corroborer | Relié au C2 principal par le certificat n°33 |
| 23 | ipv4 | `198.51.100.40` | Hébergement de la page d'hameçonnage | 2026-03-02 07:58 | C2 | aucune alerte | À corroborer |  |
| 24 | ipv4 | `203.0.113.28` | Exfiltration, volume anormal sortant (BIN-03) | 2026-03-05 15:30 | B2 | BIN-03, alerte 10 | Socle | 2,3 Go en clair, port 8080 |
| 25 | ipv4 | `198.51.100.55` | Balayage interne observé depuis poste compromis | 2026-03-03 10:12 | B3 | alerte 6 | À corroborer | Adresse du poste compromis ? Si oui, actif victime, pas infra attaquant |
| 26 | ipv4 | `203.0.113.44` | Connexion RDP entrante hors horaires | 2026-03-04 01:47 | C3 | alerte 7 (contradiction) | À corroborer | L'alerte dit « source interne », l'IoC donne une IP externe |
| 27 | ipv4 | `198.51.100.61` | Nœud intermédiaire, passive DNS partagé avec D-04 | 2026-03-03 03:22 | C4 | aucune alerte | Faible | Lien par passive DNS seulement |
| 28 | ipv4 | `203.0.113.60` | IP mentionnée dans un rapport public sur un cluster proche — à corréler, non confirmée | 2026-03-06 09:00 | D4 | hors incident | Faible | Vient d'un rapport public : à exclure de l'attribution |
| 29 | url | `hxxps://cdn-svc-update[.]test/win/svchost_update.exe` | URL de la seconde charge | 2026-03-02 08:41 | B2 | alerte 2 | Socle |  |
| 30 | url | `hxxps://mail-secure-login[.]test/owa/auth` | Page de collecte d'identifiants | 2026-03-02 07:58 | C2 | aucune alerte | À corroborer | Collecte d'identifiants : expliquerait le RDP du 4 mars (hypothèse) |
| 31 | url | `hxxps://api-telemetry-eu[.]test/v2/beacon` | Point de contact de la balise | 2026-03-02 09:15 | B2 | alerte 4 | Socle |  |
| 32 | url | `hxxps://helios-energy-portal[.]test/hr/doc` | Leurre imitant le portail RH de la victime | 2026-03-02 06:40 | B3 | aucune alerte | À corroborer | Leurre RH, alors que le courriel visait la comptabilité |
| 33 | sha1-cert | `BDA5D6C36E3FF362F9CE0957370A429FFF58EB37` | Certificat auto-signé partagé par les serveurs de commande, sujet CN=update-service | 2026-03-02 09:20 | B2 | BIN-02 | Socle | = CERT-01 ; pivot qui relie les serveurs de commande |
| 34 | sha1-cert | `0315D14DD4B9095A10E359CBAF4129F0A6322A59` | Certificat de la page d'hameçonnage | 2026-03-02 07:58 | C3 | aucune alerte | À corroborer |  |
| 35 | sha1-cert | `1E8BD87AF841CDA6441306558F11D973EB0A5601` | Certificat révélant par pivot une campagne antérieure (janvier 2026) | 2026-03-06 10:00 | C4 | hors incident | Faible | Pivot vers une campagne de janvier 2026 : hypothèse |
| 36 | host | `MicrosoftEdgeUpdateTaskMachine` | Tâche planifiée de persistance (BIN-02) | 2026-03-02 08:45 | A2 | BIN-02, alerte 3 | Socle | Imite la tâche légitime de Microsoft Edge |
| 37 | host | `svc-backup-temp` | Compte de service créé puis supprimé sur le contrôleur de domaine | 2026-03-05 14:10 | B2 | alerte 9 | Socle | Compte créé 14:10, supprimé 14:55 |
| 38 | host | `HKCU\...\Run\WinTelemetry` | Clé de registre de persistance | 2026-03-02 08:44 | A2 | BIN-01 | Socle | Persistance absente des techniques listées dans la fiche |
| 39 | host | `C:\Windows\Temp\~df3a9.tmp` | Fichier de collecte chiffré avant exfiltration | 2026-03-05 14:40 | B2 | BIN-03 | Socle |  |
| 40 | host | `comptabilite-07` | Poste d'entrée initial (patient zéro) | 2026-03-02 08:30 | A1 | alertes 1 à 4, 6, 12 | Socle | Actif victime : jamais partagé à l'extérieur |

## 4. Correspondance pour MISP (J2)

| Type du CSV | Attribut MISP | Regroupement conseillé |
|---|---|---|
| sha256, sha1, md5 (n°1 à 9) | `sha256`, `sha1`, `md5` | 3 objets `file`, un par binaire, avec nom de fichier et les 3 empreintes |
| sha256 (n°10 à 12) | `sha256` | Attributs simples, reliés à leur binaire |
| domain + ipv4 de résolution | `domain`, `ip-dst` | Objets `domain-ip` (n°13+19, n°14+20) |
| ipv4 | `ip-dst` | |
| url | `url` | |
| sha1-cert | `x509-fingerprint-sha1` | Objets `x509` |
| host n°36 | `windows-scheduled-task` | |
| host n°37 | `target-user` | |
| host n°38 | `regkey` | |
| host n°39 | `filename` | |
| host n°40 | `target-machine` | `to_ids` désactivé |

Chaque attribut porte deux tags Admiralty, par exemple pour B2 : `admiralty-scale:source-reliability="b"` et `admiralty-scale:information-credibility="2"`. Le champ commentaire reçoit la source et la date de collecte, exigées par le sujet.

## 5. Anomalies relevées dans le dossier

1. **Étiquettes des fiches et CSV ne concordent pas pour les IP.** Les fiches citent IP-07 et IP-08 comme serveurs de commande et IP-09 comme IP d'exfiltration. Dans le CSV, les 7e, 8e et 9e adresses sont le balayage interne, le RDP et un nœud intermédiaire. Par le contexte, les serveurs de commande sont les n°21 et 22 et l'exfiltration le n°24. À vérifier dans le fichier JSON (présence d'un identifiant) ou à faire arbitrer par le commanditaire.
2. **n°25, `198.51.100.55`.** Décrit comme un balayage « depuis poste compromis ». Si c'est l'adresse de comptabilite-07, c'est un actif de la victime et non une infrastructure de l'attaquant : à ne pas bloquer ni partager.
3. **n°26, `203.0.113.44`.** L'alerte 7 parle d'une « source interne inhabituelle », l'indicateur d'une IP externe cotée C3. On ne peut pas affirmer une exposition RDP sur Internet.
4. **n°18, `update-win-msft[.]test`.** Typé domaine, décrit comme un nom de tâche planifiée, sans alerte associée. Rôle à clarifier.
5. **n°28 et n°35.** Datés du 6 mars, ce sont des éléments de recherche (rapport public, pivot de certificat), pas des observations de l'incident. Ils ne peuvent pas porter l'attribution.
6. **Deux leurres différents.** Portail RH (n°17, 32) et facture adressée à la comptabilité (BIN-01). D'autres salariés ont peut-être été visés : question de périmètre à poser.
