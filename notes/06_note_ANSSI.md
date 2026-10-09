# Note réglementaire — déclaration à l'ANSSI

**Incident** : INC-2026-0302 · **Classification** : TLP:AMBER · **Version** : 1.0 du 9 octobre 2026 · **Destinataires** : direction générale, RSSI, direction juridique · **Auteurs** : cellule CTI (Marc BOHOUSSOU, [Nom 2], [Nom 3])

## 1. Qualification de l'incident

Intrusion ciblée dans le système d'information d'Helios Energy, opérateur d'importance vitale du secteur de l'énergie, entre le 2 et le 7 mars 2026 :

- compromission d'un poste, d'un serveur de fichiers et du **contrôleur de domaine** `dc-01` ;
- **vol d'identifiants** du domaine (alerte 5) ;
- **exfiltration de 2,3 Go** vers une adresse externe (alerte 10), contenu non établi ;
- attaquant **encore actif** les 6 et 7 mars, après la détection.

Il s'agit d'un incident de sécurité **majeur**. Aucune atteinte aux systèmes industriels n'est observée, mais l'annuaire compromis est susceptible d'authentifier des accès à des systèmes d'information d'importance vitale (SIIV).

## 2. Ce qui doit être déclaré, à qui, dans quel délai

| Obligation | Destinataire | Délai | Fondement | S'applique ici ? |
|---|---|---|---|---|
| Déclaration d'incident affectant un SIIV | **ANSSI** (CERT-FR), pour le compte du Premier ministre, par le formulaire de déclaration d'incident ou le téléservice de l'agence | **Sans délai** dès la connaissance de l'incident | Code de la défense, art. L. 1332-6-2 | **Oui si** `dc-01` ou l'annuaire entre dans le périmètre ou l'administration d'un SIIV. À défaut, déclaration volontaire recommandée |
| Notification d'une violation de données personnelles | **CNIL** | **72 heures** après en avoir pris connaissance | RGPD, art. 33 | **Oui** : les identifiants des salariés sont des données personnelles |
| Information des personnes concernées | Salariés, et clients si leurs données figurent dans les 2,3 Go | Dans les meilleurs délais | RGPD, art. 34 | Si le risque pour les personnes est élevé : dépend de l'inventaire |
| Dépôt de plainte | Police ou gendarmerie, parquet | **72 heures** pour préserver l'indemnisation par une assurance cyber | Code des assurances, art. L. 12-10-1 | Recommandé dans tous les cas |

## 3. Contenu de la déclaration à l'ANSSI

Identité de l'opérateur et point de contact joignable à toute heure ; systèmes touchés et lien avec les SIIV ; date de détection (2 mars 2026, 08:31 UTC) et chronologie connue ; nature (hameçonnage ciblé, implant, vol d'identifiants, exfiltration) ; impacts constatés et redoutés (voir la matrice CID) ; mesures prises et prévues ; éléments techniques, soit les indicateurs cotés A1 à B2 et le bundle STIX, transmis en TLP:AMBER.

La déclaration est **évolutive** : une première version factuelle part immédiatement, puis elle est complétée à mesure que l'analyse avance. Attendre d'avoir tout compris serait une faute.

## 4. Calendrier

| Moment | Action |
|---|---|
| 2 mars, ouverture de l'incident | Alerte interne du RSSI et de la direction |
| Au plus tard le 5 mars, compromission de `dc-01` | Déclaration initiale à l'ANSSI. Si elle n'a pas été faite, **la faire immédiatement** en expliquant le retard |
| 72 h après la connaissance de la fuite | Notification à la CNIL, dépôt de plainte |
| À chaque avancée | Compléments à l'ANSSI : indicateurs, périmètre, remédiation |
| Clôture | Rapport final : cause, impact réel, mesures correctives |

## 5. Deux points d'attention

- **NIS 2.** La directive prévoit une alerte sous 24 heures, une notification sous 72 heures et un rapport final sous un mois. Sa transposition française (projet de loi « Résilience ») n'était pas promulguée à la date de cette note : ces délais ne s'imposent pas encore, mais ils constituent un bon calendrier de travail et le régime actuel, « sans délai », est au moins aussi exigeant.
- **Arbitrage attendu.** Le périmètre exact des SIIV d'Helios Energy n'est pas dans le dossier. Le RSSI doit confirmer si l'annuaire en relève. Dans le doute, déclarer.

*Note établie par une cellule de renseignement technique. Les références juridiques sont à faire valider par la direction juridique.*
