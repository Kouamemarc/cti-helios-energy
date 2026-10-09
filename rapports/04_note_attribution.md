# Note d'attribution — INC-2026-0302

**Classification** : TLP:AMBER · **Version** : 1.0 du 9 octobre 2026 · **Auteurs** : cellule CTI (Marc BOHOUSSOU, [Nom 2], [Nom 3])

## 1. Jugement

> L'intrusion est attribuée à un **cluster d'activité non nommé**, désigné ici **HELIOS-C1**, très probablement **cybercriminel et à motivation financière**. Son outillage présente un **recouvrement partiel** avec la famille Carbanak/FIN7. Nous **n'attribuons pas** l'attaque à FIN7, et **aucun artefact** ne soutient l'hypothèse d'un acteur étatique.
>
> **Niveau de confiance : moyen (cote Admiralty B3).**

| Jugement | Cote | Lecture |
|---|---|---|
| J1. BIN-01 et BIN-02 viennent du même outilleur | A2 | Source fiable, information probablement vraie |
| J2. L'acteur est cybercriminel, à motivation financière | B3 | Possiblement vraie : cohérente, mais sans preuve directe du mobile |
| J3. L'outillage recoupe partiellement la famille Carbanak/FIN7 | B3 | Un seul indice technique, signalé « à valider » par sa source |
| J4. L'acteur est FIN7 | C4 | Douteuse : non retenue |
| J5. L'acteur est étatique | — / 5 | Improbable au vu du dossier : aucun artefact ne l'appuie |

## 2. Méthode

Nous avons comparé trois hypothèses concurrentes, en cherchant pour chacune ce qui la contredit plutôt que ce qui la confirme. Seuls les indicateurs cotés A1 à B2 portent l'argumentation. Les sources publiques (fiches MITRE ATT&CK du groupe G0046 et du logiciel S0030, consultées le 9 octobre 2026) servent à comparer, jamais à compléter la chaîne d'attaque.

## 3. Les éléments de preuve

| # | Élément | Artefact | Cote | Ce qu'il prouve | Ce qu'il ne prouve pas |
|---|---|---|---|---|---|
| E1 | Chaîne « build 7.3 » commune à BIN-01 et BIN-02 | Fiches BIN-01, BIN-02 | A2 | Un même outilleur pour le classeur piégé et la balise | L'identité de l'opérateur : un outil peut être vendu ou loué |
| E2 | Format de balise, intervalle de 300 s avec variation de 20 % | Fiche BIN-02, alerte 4 | B3 | Une ressemblance avec des outils cybercriminels décrits publiquement | Une filiation : la variation aléatoire est un réglage courant des outils de commande |
| E3 | Leurre « facture » adressé à la comptabilité | BIN-01, mémo | A1 | Un appât à thème financier | Le mobile réel |
| E4 | Domaine imitant la victime | n°17, n°32 | B3 | Un ciblage délibéré d'Helios Energy | Qui cible |
| E5 | Vol d'identifiants, exfiltration de 2,3 Go, effacement de journaux | Alertes 5, 10, 12 | A2 à B2 | Un enchaînement typique d'une préparation à l'extorsion | Qu'une extorsion aura lieu : aucun chiffrement, aucune demande de rançon |
| E6 | Exfiltration en clair sur le port 8080 | Alerte 10 | B2 | Une discrétion faible, peu compatible avec de l'espionnage patient | — |
| E7 | BIN-03, outil générique de vol d'identifiants | Fiche BIN-03 | A1 | Rien pour l'attribution : « très largement partagé » selon la fiche | — |
| E8 | Commentaires en anglais dans la macro | Fiche BIN-01 | A2 | Rien : l'anglais est la langue de travail de tout l'écosystème | Une nationalité |

**Éléments écartés de l'argumentation**

| Indicateur | Cote | Raison |
|---|---|---|
| n°28, IP citée dans un rapport public sur un « cluster proche » | D4 | Non observée dans l'incident, source non évaluable, information douteuse |
| n°35, certificat menant par pivot à une campagne de janvier 2026 | C4 | Pivot non confirmé, daté du 6 mars, après les faits |
| n°27, nœud intermédiaire | C4 | Lien par DNS passif seulement |

Ces trois indicateurs sont les seuls qui relieraient l'incident à une activité antérieure connue. Les utiliser reviendrait à bâtir l'attribution sur ses éléments les plus fragiles.

## 4. Confrontation des hypothèses

| Élément | H-A : cluster cybercriminel non nommé | H-B : FIN7 lui-même | H-C : acteur étatique |
|---|---|---|---|
| E1 outilleur commun | Compatible | Compatible | Compatible |
| E2 format de balise | Compatible | Compatible | Neutre |
| E3 leurre financier | Compatible | Compatible | Peu compatible |
| E4 ciblage de la victime | Compatible | Compatible | Compatible |
| E5 préparation à l'extorsion | Compatible | Compatible | Peu compatible |
| E6 exfiltration bruyante | Compatible | Compatible | **Contredit** |
| E7 outil générique | Compatible | Neutre | Peu compatible |
| Absence de tout lien d'infrastructure fiable avec un groupe connu | Compatible | **Contredit** | Neutre |
| Aucune action sur les systèmes industriels | Compatible | Compatible | **Contredit** l'hypothèse du sabotage |

H-A est la seule hypothèse qu'aucun élément ne contredit.

## 5. Comparaison avec FIN7 et Carbanak

Sur les 25 techniques validées dans le dossier, au moins 12 figurent sur la fiche ATT&CK de FIN7 (G0046) : T1566.001, T1204.002, T1059.001, T1547.001, T1053.005, T1036.004, T1027, T1105, T1008, T1021.001, T1543.003, T1583.001.

Ce recouvrement ne suffit pas, pour trois raisons.

1. **Ces 12 techniques sont parmi les plus répandues.** Hameçonnage par pièce jointe, PowerShell, tâche planifiée, clé Run et RDP sont employés par des dizaines de groupes.
2. **Les techniques les plus caractéristiques du dossier n'y figurent pas** : creux de processus (T1055.012), balise HTTPS (T1071.001, T1573), lecture de LSASS (T1003.001), exfiltration en clair (T1048.003).
3. **L'indice central ne se recoupe pas.** La fiche ATT&CK du logiciel Carbanak (S0030) décrit des échanges en HTTP et une injection d'exécutable (T1055.002), pas un creux de processus, et ne mentionne ni intervalle ni variation aléatoire de la balise. La ressemblance signalée par la fiche BIN-02 reste donc portée par une seule source.

À l'inverse, deux points empêchent d'écarter totalement la piste : FIN7 pratique l'extorsion par rançongiciel depuis 2020 et compte les services collectifs (« utilities ») parmi ses secteurs visés, principalement aux États-Unis. D'où la formulation retenue : recouvrement partiel, pas attribution.

## 6. Diamond Model

| Sommet | Contenu | Artefacts |
|---|---|---|
| **Adversaire** | Cluster HELIOS-C1, non nommé. Outilleur identifiable par « build 7.3 » | Fiches BIN-01, BIN-02 |
| **Capacité** | Classeur à macro (BIN-01), balise HTTPS empaquetée (BIN-02), outil de vol d'identifiants (BIN-03), PowerShell, RDP, wevtutil | Fiches, alertes 1, 5, 7, 8, 12 |
| **Infrastructure** | Livraison `cdn-svc-update[.]test` ; commande `api-telemetry-eu[.]test` et 203.0.113.14 ; repli `static-assets-cache[.]test` ; certificat auto-signé `CN=update-service` ; hameçonnage `mail-secure-login[.]test` ; exfiltration 203.0.113.28:8080 | n°13 à 16, 19 à 24, 33 |
| **Victime** | Helios Energy, opérateur d'importance vitale du secteur de l'énergie. Service comptabilité, puis serveur de fichiers et contrôleur de domaine | n°40, alertes 5 à 10 |

Axe adversaire-victime : mobile financier probable. Axe capacité-infrastructure : environnement Windows et Active Directory, sans composant visant les systèmes industriels.

## 7. Biais possibles

| Biais | Comment il peut jouer ici | Parade appliquée |
|---|---|---|
| **Ancrage** | La fiche BIN-02 et le dossier citent FIN7/Carbanak : on est tenté de partir de ce nom | Hypothèses concurrentes formulées avant la comparaison |
| **Confirmation** | Ne retenir que les techniques communes avec FIN7 | Recherche systématique de ce qui manque et de ce qui contredit (section 5) |
| **Victimologie** | « Un opérateur d'énergie est forcément visé par un État » | H-C testée contre les artefacts : aucun ne l'appuie |
| **Disponibilité** | FIN7 est très documenté, donc facile à « reconnaître » partout | Les 12 techniques communes sont qualifiées de génériques |
| **Faux drapeau et outils partagés** | Un acteur peut imiter ou réutiliser un outillage connu, vendu ou divulgué | L'attribution porte sur un cluster, pas sur un groupe nommé |
| **Source unique** | Tous les artefacts viennent du même SOC ; le mémo a été complété sans changer sa date | Cote du mémo ramenée à B ; incohérences relevées |
| **Renseignement circulaire** | Les indicateurs n°28 et n°35 viennent de recherches postérieures à l'incident | Exclus de l'argumentation |

## 8. Ce qui ferait évoluer le jugement

- **Vers le haut** : une revendication ou une demande de rançon, l'extraction de la configuration de BIN-02, une comparaison de code avec des familles connues, la confirmation indépendante du pivot de certificat n°35.
- **Vers le bas ou ailleurs** : la découverte d'une action sur les systèmes industriels, d'un outillage sur mesure, ou d'un second accès sans lien avec HELIOS-C1.

## 9. Limites

- Les indicateurs sont fictifs (plages de documentation, domaines en `.test`) : aucune vérification en sources ouvertes n'est possible.
- Nous ne disposons ni des en-têtes du courriel initial, ni d'une image mémoire, ni des journaux du serveur de fichiers entre le 4 et le 5 mars.
- Les horodatages d'activité sont trop peu nombreux pour en déduire un fuseau horaire de travail.
