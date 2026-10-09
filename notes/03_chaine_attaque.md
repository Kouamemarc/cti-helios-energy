# Chaîne d'attaque — INC-2026-0302

Version de travail, J1. Chaque ligne renvoie à un artefact du dossier : alerte SIEM (A1 à A12), indicateur (n°1 à 40) ou fiche binaire (BIN-01 à 03). Heures en UTC. J0 = 2 mars 2026.

## 1. Chronologie reconstituée

Les 12 alertes sont retriées par horodatage : dans le fichier fourni, l'alerte 5 (5 mars) est placée avant les alertes 6 à 8 (3 et 4 mars).

| Jour | Heure | Hôte | Événement | Artefacts |
|---|---|---|---|---|
| J0, 2 mars | 06:40 | externe | Domaine imitant Helios Energy et leurre « portail RH » en ligne | n°17, 32 |
| | 07:58 | externe | Page de collecte d'identifiants en ligne | n°15, 23, 30, 34 |
| | 08:30 | comptabilite-07 | Ouverture de `facture_mars_2026.xlsm` | BIN-01, n°1 à 3, 40 |
| | 08:31 | comptabilite-07 | Application Office qui lance PowerShell encodé, fenêtre masquée | A1, n°10 |
| | 08:42 | comptabilite-07 | Téléchargement de `svchost_update.exe` | A2, n°13, 19, 29, BIN-02 |
| | 08:44 | comptabilite-07 | Clé de registre Run `WinTelemetry` | n°38, BIN-01 |
| | 08:46 | comptabilite-07 | Tâche planifiée `MicrosoftEdgeUpdateTaskMachine` | A3, n°36 |
| | 09:16 | comptabilite-07 | Balise HTTPS toutes les 300 s environ | A4, n°14, 20, 21, 31, 33 |
| | 10:30 | — | Mémo initial du SOC | mémo |
| J1, 3 mars | 02:00 à 03:22 | externe | Infrastructure de repli observée | n°16, 22, 27 |
| | 10:13 | comptabilite-07 | Balayage de 10.20.0.0/16 sur les ports 445 et 3389 | A6, n°25 |
| J2, 4 mars | 01:48 | srv-fichiers-02 | Session RDP hors horaires | A7, n°26 |
| | 11:05 | srv-fichiers-02 | Injection de code dans `explorer.exe` | A8, n°11 |
| J3, 5 mars | 14:05 | dc-01 | Dépôt de `rundll32_helper.dll` | BIN-03, n°7 à 9 |
| | 14:07 | dc-01 | Lecture de la mémoire de LSASS | A5 |
| | 14:10 | dc-01 | Compte `svc-backup-temp` créé (supprimé à 14:55) | A9, n°37 |
| | 14:40 | dc-01 | Fichier de collecte chiffré dans `C:\Windows\Temp` | n°39, 12 |
| | 15:31 | dc-01 | 2,3 Go sortants en clair vers 203.0.113.28:8080 | A10, n°24 |
| J4, 6 mars | 03:10 | srv-fichiers-02 | Bascule vers le domaine de repli | A11, n°16 |
| J5, 7 mars | 09:02 | comptabilite-07 | Effacement du journal Sécurité (`wevtutil cl Security`) | A12 |

## 2. Techniques ATT&CK validées par les artefacts

Référentiel : ATT&CK v19. Depuis cette version, l'ancienne tactique « Defense Evasion » est scindée en « Stealth » (furtivité) et « Defense Impairment » (affaiblissement des défenses). Les alertes du dossier utilisent encore l'ancienne numérotation pour une technique : T1070.001 est devenue T1685.005.

| Tactique | Technique | Preuve | Solidité |
|---|---|---|---|
| Développement de ressources | T1583.001 Acquisition de domaines | n°13, 14, 17 | Moyenne |
| | T1587.003 Certificats numériques (auto-signé) | n°33 | Moyenne |
| Accès initial | T1566.001 Pièce jointe d'hameçonnage ciblé | BIN-01, mémo | Forte |
| Exécution | T1204.002 Fichier malveillant | BIN-01, mémo | Forte |
| | T1059.001 PowerShell | A1, BIN-01, n°10 | Forte |
| Persistance | T1547.001 Clé de registre Run | n°38, BIN-01 | Forte |
| | T1053.005 Tâche planifiée | A3, n°36, BIN-02 | Forte |
| | T1543.003 Service Windows créé puis supprimé | BIN-03 | Forte |
| | T1136.002 Création d'un compte de domaine | A9, n°37 | Forte |
| Furtivité (Stealth) | T1027 Charge encodée (base64) | A1, BIN-01 | Forte |
| | T1564.003 Fenêtre masquée | A1 | Forte |
| | T1027.002 Empaquetage (UPX modifié) | BIN-02 | Forte |
| | T1036.004 Tâche qui imite un nom légitime | n°36 | Forte |
| | T1055.012 Creux de processus | A8, BIN-02, n°11 | Forte |
| Affaiblissement des défenses | T1685.005 Effacement des journaux Windows (ex-T1070.001) | A12 | Forte |
| Commande et contrôle | T1105 Transfert d'outil | A2, n°29 | Forte |
| | T1071.001 Protocoles web | A4, BIN-02, n°31 | Forte |
| | T1573 Canal chiffré | BIN-02, n°33 | Forte |
| | T1008 Canal de repli | A11, n°16 | Moyenne |
| Découverte | T1046 Balayage de services réseau | A6 | Forte |
| Mouvement latéral | T1021.001 RDP | A7 | Moyenne |
| Accès aux identifiants | T1003.001 Mémoire de LSASS | A5, BIN-03 | Forte |
| Collecte | T1074.001 Mise en attente locale | BIN-03, n°39 | Forte |
| | T1560 Archive chiffrée | n°12, 39 | Moyenne |
| Exfiltration | T1048.003 Protocole non chiffré hors C2 | A10, n°24 | Forte |

Soit 25 techniques. Deux points à défendre plutôt qu'à recopier :

- **A9 est étiquetée T1543.003 (service Windows)**, mais son détail décrit la création d'un *compte* dans l'Active Directory, ce qui correspond à T1136.002. T1543.003 reste valable pour BIN-03, dont la fiche décrit un service créé puis supprimé. Les deux sont retenues, avec des preuves différentes.
- **T1566.002 (lien d'hameçonnage)** est possible à cause de la page de collecte d'identifiants (n°15, 30), mais aucune alerte ne montre qu'un salarié y a saisi son mot de passe. Elle reste une hypothèse et n'est pas comptée.

## 3. Constats qui comptent pour la suite

1. **L'hypothèse du SOC est contredite par les horodatages.** Le mémo suppose un vol d'identifiants sur dc-01 suivi d'un déplacement vers les serveurs de fichiers. Or srv-fichiers-02 est atteint le 4 mars, avant l'accès à LSASS du 5 mars. L'attaquant disposait donc déjà d'identifiants valides le 4.
2. **L'attaquant est resté actif après la détection.** Le poste d'entrée, signalé le 2 mars, efface encore ses journaux le 7 mars, et srv-fichiers-02 bascule sur le canal de repli le 6. Le poste n'a pas été isolé et l'implant du serveur de fichiers fonctionne toujours. Cela répond en partie à la question « l'attaquant est-il toujours présent ? ».
3. **Le contrôleur de domaine est compromis.** Lecture de LSASS sur dc-01 : tous les identifiants du domaine doivent être considérés comme exposés.
4. **Aucun chiffrement n'est observé.** La phase de rançongiciel évoquée par le commanditaire est un scénario de risque, appuyé par des signes avant-coureurs (vol d'identifiants, exfiltration, effacement de traces), pas un fait.
5. **Le ciblage est délibéré.** Un domaine imite spécifiquement la victime (n°17), ce qui écarte une campagne de masse.

## 4. Incohérences du dossier à signaler

- **Mémo daté du 2 mars à 10:30, mais il décrit des faits du 5 mars** (« trois jours plus tard », « le quatrième jour »). Il a été complété sans mise à jour de la date : à prendre en compte dans la cote de cette source.
- **A1 cite `winword.exe`, alors que BIN-01 est un classeur Excel.** Soit le détail de l'alerte est erroné, soit un second document existe. Conséquence pratique : la règle Sigma devra couvrir toutes les applications Office comme processus parent.
- **A7 et n°26 se contredisent** sur l'origine de la session RDP (interne ou externe).
- **Le fichier d'alertes n'est pas dans l'ordre chronologique**, contrairement à ce qu'indique le LISEZ-MOI.

## 5. Zones d'ombre

- Quels identifiants ont servi pour le RDP du 4 mars, et d'où viennent-ils ?
- Comment l'attaquant est passé de srv-fichiers-02 à dc-01 : aucune alerte entre le 4 mars 11:05 et le 5 mars 14:05.
- Contenu des 2,3 Go exfiltrés.
- D'autres postes ont-ils reçu le leurre « portail RH » ?

## 6. Actifs touchés (base de la matrice CID)

| Actif | Rôle | Ce qui est prouvé |
|---|---|---|
| comptabilite-07 | Poste de travail, point d'entrée | Exécution, persistance, balise, balayage, effacement de journaux |
| srv-fichiers-02 | Serveur de fichiers | Session RDP illégitime, implant injecté, canal de repli |
| dc-01 | Contrôleur de domaine | Vol d'identifiants, compte éphémère, mise en attente et exfiltration |
