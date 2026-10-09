#!/usr/bin/env python3
"""Complète l'export STIX 2.1 de MISP pour obtenir le bundle final du projet.

Usage :  python stix/enrichir_bundle.py stix/misp_export_stix2.json stix/bundle_helios.json

MISP exporte les indicateurs, les observables, leurs relations et les galaxies.
Ce script ajoute ce que MISP ne modélise pas directement :
  - le cluster d'activité HELIOS-C1 (objet intrusion-set) et la victime ;
  - les trois outils (BIN-01, BIN-02, BIN-03) reliés à leurs empreintes ;
  - les liens outil -> technique ATT&CK, chacun justifié par un artefact ;
  - le lien « recouvrement partiel » vers FIN7, si la galaxie est présente ;
  - la source et la date de collecte sur chaque objet qui n'en porte pas.
Rien n'est inventé : chaque ajout cite l'alerte, l'indicateur ou la fiche qui le fonde.
"""
import json
import sys
import uuid
from datetime import datetime, timezone

SOURCE = "Dossier d'artefacts SOC Helios Energy - INC-2026-0302"
COLLECTE = "2026-10-06"
ANALYSE = "Cellule CTI - projet Helios Energy"
NS = uuid.UUID("1c56b296-c18e-4771-ba9b-e7ed7112f56f")  # UUID de l'événement MISP : identifiants stables
TLP_AMBER = "marking-definition--f88d31f6-486f-44da-b317-01333bde0b82"

# Technique -> (nom, outil porteur, preuve). Outil : BIN-01, BIN-02, BIN-03 ou ACTEUR.
TECHNIQUES = {
    "T1583.001": ("Acquire Infrastructure: Domains", "ACTEUR", "Indicateurs n°13, 14, 17"),
    "T1587.003": ("Develop Capabilities: Digital Certificates", "ACTEUR", "Indicateur n°33, certificat auto-signé"),
    "T1566.001": ("Phishing: Spearphishing Attachment", "BIN-01", "Fiche BIN-01, mémo SOC"),
    "T1204.002": ("User Execution: Malicious File", "BIN-01", "Fiche BIN-01, mémo SOC"),
    "T1059.001": ("Command and Scripting Interpreter: PowerShell", "BIN-01", "Alerte 1, indicateur n°10"),
    "T1027": ("Obfuscated Files or Information", "BIN-01", "Alerte 1, charge encodée en base64"),
    "T1564.003": ("Hide Artifacts: Hidden Window", "BIN-01", "Alerte 1, option -w hidden"),
    "T1547.001": ("Boot or Logon Autostart Execution: Registry Run Keys", "BIN-01", "Indicateur n°38, fiche BIN-01"),
    "T1105": ("Ingress Tool Transfer", "BIN-01", "Alerte 2, indicateur n°29"),
    "T1053.005": ("Scheduled Task/Job: Scheduled Task", "BIN-02", "Alerte 3, indicateur n°36"),
    "T1036.004": ("Masquerading: Masquerade Task or Service", "BIN-02", "Indicateur n°36, nom imitant Edge Update"),
    "T1027.002": ("Obfuscated Files or Information: Software Packing", "BIN-02", "Fiche BIN-02, UPX modifié"),
    "T1055.012": ("Process Injection: Process Hollowing", "BIN-02", "Alerte 8, indicateur n°11"),
    "T1071.001": ("Application Layer Protocol: Web Protocols", "BIN-02", "Alerte 4, indicateur n°31"),
    "T1573": ("Encrypted Channel", "BIN-02", "Fiche BIN-02, indicateur n°33"),
    "T1008": ("Fallback Channels", "BIN-02", "Alerte 11, indicateur n°16"),
    "T1046": ("Network Service Discovery", "ACTEUR", "Alerte 6"),
    "T1021.001": ("Remote Services: Remote Desktop Protocol", "ACTEUR", "Alerte 7"),
    "T1136.002": ("Create Account: Domain Account", "ACTEUR", "Alerte 9, indicateur n°37"),
    "T1003.001": ("OS Credential Dumping: LSASS Memory", "BIN-03", "Alerte 5, fiche BIN-03"),
    "T1543.003": ("Create or Modify System Process: Windows Service", "BIN-03", "Fiche BIN-03"),
    "T1074.001": ("Data Staged: Local Data Staging", "BIN-03", "Fiche BIN-03, indicateur n°39"),
    "T1560": ("Archive Collected Data", "BIN-03", "Indicateurs n°12 et 39"),
    "T1048.003": ("Exfiltration Over Unencrypted Non-C2 Protocol", "ACTEUR", "Alerte 10, indicateur n°24"),
    "T1685.005": ("Clear Windows Event Logs (ex-T1070.001)", "ACTEUR", "Alerte 12"),
}
ANCIENS_ID = {"T1070.001": "T1685.005"}  # numérotation d'avant ATT&CK v19

OUTILS = {
    "BIN-01": dict(type="malware", name="BIN-01 facture_mars_2026.xlsm", is_family=False, malware_types=["dropper"],
                   sha256="2d10d13c3f3a045dc12a48e0a484018c053d0e83c607f2796fc9b8307c0d66e5",
                   description="Classeur Office à macro VBA, dropper. Chaîne « build 7.3 » commune avec BIN-02. Source : fiche BIN-01."),
    "BIN-02": dict(type="malware", name="BIN-02 svchost_update.exe", is_family=False, malware_types=["backdoor"],
                   sha256="cdf03e90d85977619f7881a13f59a275812dbf0e4ae29874493728b0ef78ebc9",
                   description="Balise de commande et contrôle, HTTPS toutes les 300 s (+/- 20 %). Source : fiche BIN-02."),
    "BIN-03": dict(type="malware", name="BIN-03 rundll32_helper.dll", is_family=False, malware_types=["spyware"],
                   sha256="f4109cd2860816d568c5581edf8ed5df28d35471fa8ff849e9ee2451b69135f0",
                   description="Outil générique d'extraction d'identifiants (LSASS), très largement partagé. Source : fiche BIN-03."),
}

# Liens complémentaires (source, relation, valeur de l'indicateur, preuve)
LIENS = [
    ("BIN-02", "downloaded-from", "https://cdn-svc-update.test/win/svchost_update.exe", "Alerte 2, indicateur n°29"),
    ("BIN-02", "communicates-with", "https://api-telemetry-eu.test/v2/beacon", "Alerte 4, indicateur n°31"),
    ("BIN-02", "communicates-with", "static-assets-cache.test", "Alerte 11 : bascule sur le domaine de repli (n°16, cote C3)"),
    ("ACTEUR", "related-to", "svc-backup-temp", "Alerte 9 : compte créé puis supprimé sur dc-01 (n°37)"),
    ("ACTEUR", "related-to", "mail-secure-login.test", "Page d'hameçonnage liée au courriel initial (n°15, cote C2)"),
    ("ACTEUR", "related-to", "helios-energy-portal.test", "Domaine d'usurpation imitant la victime (n°17, cote B3)"),
]


def sid(kind, key):
    return f"{kind}--{uuid.uuid5(NS, kind + '|' + key)}"


def main(src, dst):
    bundle = json.load(open(src, encoding="utf-8"))
    objs = bundle["objects"]
    by_id = {o["id"]: o for o in objs}
    now = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.000Z")
    createur = next((o["id"] for o in objs if o["type"] == "identity"), None)
    if TLP_AMBER not in by_id:
        objs.append({"type": "marking-definition", "spec_version": "2.1", "id": TLP_AMBER,
                     "created": "2017-01-20T00:00:00.000Z", "definition_type": "tlp",
                     "name": "TLP:AMBER", "definition": {"tlp": "amber"}})
    ajoutes = []

    def sdo(kind, key, **props):
        o = {"type": kind, "spec_version": "2.1", "id": sid(kind, key), "created": now, "modified": now,
             "object_marking_refs": [TLP_AMBER], **props}
        if createur:
            o["created_by_ref"] = createur
        o.setdefault("external_references", [{"source_name": ANALYSE, "description": f"Analyse du {now[:10]} fondée sur : {SOURCE}"}])
        ajoutes.append(o)
        return o["id"]

    def rel(a, kind, b, preuve, confidence=None):
        props = dict(relationship_type=kind, source_ref=a, target_ref=b, description=preuve)
        if confidence is not None:
            props["confidence"] = confidence
        return sdo("relationship", f"{a}|{kind}|{b}", **props)

    # 1. Acteur et victime
    acteur = sdo("intrusion-set", "HELIOS-C1", name="HELIOS-C1",
                 description=("Cluster d'activité non nommé, à l'origine de l'intrusion INC-2026-0302. Cybercriminel à "
                              "motivation financière probable. Recouvrement partiel d'outillage avec la famille "
                              "Carbanak/FIN7 : ce n'est pas une attribution. Confiance moyenne, cote Admiralty B3."),
                 first_seen="2026-03-02T06:40:00.000Z", last_seen="2026-03-07T09:02:00.000Z",
                 primary_motivation="personal-gain", confidence=50,
                 labels=['admiralty-scale:source-reliability="b"', 'admiralty-scale:information-credibility="3"'])
    victime = sdo("identity", "victime", name="Helios Energy", identity_class="organization", sectors=["energy"],
                  description="Victime. Opérateur d'importance vitale (entreprise fictive). À retirer avant tout partage externe.")
    rel(acteur, "targets", victime, "Domaine d'usurpation (n°17), postes et serveurs touchés (alertes 1 à 12)")

    # 2. Outils, reliés à l'acteur et à leurs empreintes
    outil_id = {}
    for code, d in OUTILS.items():
        d = dict(d)
        sha = d.pop("sha256")
        kind = d.pop("type")
        outil_id[code] = sdo(kind, code, **d)
        rel(acteur, "uses", outil_id[code], f"Fiche {code}")
        vus = [o["id"] for o in objs if o["type"] == "indicator" and sha in o.get("pattern", "").lower()]
        for i in vus:
            rel(i, "indicates", outil_id[code], f"Empreinte SHA-256 de {code} (cote A1)")
        if not vus:  # export sans indicateur : on rattache l'observable
            for o in objs:
                if o["type"] == "file" and o.get("hashes", {}).get("SHA-256", "").lower() == sha:
                    rel(outil_id[code], "related-to", o["id"], f"Fichier observé correspondant à {code}")
    rel(outil_id["BIN-01"], "drops", outil_id["BIN-02"], "Fiche BIN-01 et alerte 2 : la macro télécharge la seconde charge")

    # 2 bis. Liens que l'analyse établit et que l'événement MISP ne porte pas encore
    def trouver(valeur):
        for o in objs:
            if o["type"] == "indicator" and f"'{valeur}'" in o.get("pattern", ""):
                return o["id"]
        for o in objs:
            if o.get("value") == valeur or o.get("x_misp_value") == valeur:
                porteur = next((d["id"] for d in objs if d["type"] == "observed-data" and o["id"] in d.get("object_refs", [])), None)
                return porteur or o["id"]
        return None

    for source, kind, valeur, preuve in LIENS:
        cible = trouver(valeur)
        if cible:
            rel(acteur if source == "ACTEUR" else outil_id[source], kind, cible, preuve)
        else:
            print(f"  (indicateur absent de l'export, lien ignoré : {valeur})")

    # 3. Techniques : on réutilise celles exportées par MISP, on ajoute celles qui manquent
    presentes = {}
    for o in objs:
        if o["type"] == "attack-pattern":
            for r in o.get("external_references", []):
                if r.get("external_id"):
                    presentes[ANCIENS_ID.get(r["external_id"], r["external_id"])] = o["id"]
    for tid, (nom, porteur, preuve) in TECHNIQUES.items():
        ap = presentes.get(tid) or sdo(
            "attack-pattern", tid, name=nom, description=f"{nom} - {tid}. Preuve : {preuve}.",
            external_references=[{"source_name": "mitre-attack", "external_id": tid,
                                  "url": f"https://attack.mitre.org/techniques/{tid.replace('.', '/')}/"},
                                 {"source_name": ANALYSE, "description": f"Technique validée par : {preuve} ({SOURCE})"}])
        rel(acteur if porteur == "ACTEUR" else outil_id[porteur], "uses", ap, preuve)

    # 4. Lien prudent vers FIN7, seulement si la galaxie a été posée dans MISP
    for o in objs:
        if o["type"] in ("threat-actor", "intrusion-set") and "fin7" in o.get("name", "").lower():
            rel(acteur, "related-to", o["id"],
                "Recouvrement partiel d'outillage (format de balise de BIN-02). Pas une attribution. Cote B3.", confidence=50)

    # 5. Source et date de collecte sur tout objet de renseignement qui n'en porte pas
    sans_refs = {"relationship", "marking-definition"}
    for o in objs:
        if "created" not in o or o["type"] in sans_refs or o["id"] == createur:
            continue  # observables bruts (SCO) : pas de champ prévu par la norme
        refs = o.setdefault("external_references", [])
        if not any(r.get("source_name") == SOURCE for r in refs):
            refs.append({"source_name": SOURCE, "description": f"Collecté le {COLLECTE}"})

    connus = {o["id"] for o in objs}
    objs.extend(o for o in ajoutes if o["id"] not in connus)
    # Le conteneur de l'événement référence aussi les objets ajoutés
    for o in objs:
        if o["type"] in ("grouping", "report"):
            o["object_refs"] = list(dict.fromkeys(o.get("object_refs", []) + [a["id"] for a in ajoutes]))
    json.dump(bundle, open(dst, "w", encoding="utf-8"), ensure_ascii=False, indent=2)

    # Contrôles
    ids = {o["id"] for o in objs}
    rels = [o for o in objs if o["type"] == "relationship"]
    orphelins = [r["id"] for r in rels if r["source_ref"] not in ids or r["target_ref"] not in ids]
    lies = {r["source_ref"] for r in rels} | {r["target_ref"] for r in rels}
    versions = {o.get("spec_version") for o in objs}
    print(f"Bundle écrit : {dst}")
    print(f"  objets : {len(objs)}  dont relations : {len(rels)}  objets liés par au moins une relation : {len(lies)}")
    print(f"  ajoutés par ce script : {len(ajoutes)}  techniques déjà présentes dans l'export MISP : {len(presentes)}")
    print(f"  versions STIX : {versions}  relations pointant dans le vide : {len(orphelins)}")
    if len(lies) < 25:
        print("  ATTENTION : moins de 25 objets liés, le sujet en exige au moins 25.")
    try:
        import stix2
        stix2.parse(json.dumps(bundle), allow_custom=True)
        print("  validation stix2 : OK")
    except ImportError:
        print("  validation stix2 non faite (pip install stix2)")


if __name__ == "__main__":
    if len(sys.argv) != 3:
        sys.exit(__doc__)
    main(sys.argv[1], sys.argv[2])
