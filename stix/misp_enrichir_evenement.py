#!/usr/bin/env python3
"""
Enrichit l'événement MISP INC-2026-0302 (Helios Energy) :
  1. crée les objets manquants (user-account, x509, cibles srv-fichiers-02 et dc-01) ;
  2. crée les relations entre objets et attributs ;
  3. complète first_seen et cotes Admiralty manquants à partir de 02_indicateurs_40.json ;
  4. attache les techniques MITRE ATT&CK (galaxie mitre-attack-pattern).

Usage
  Simulation hors ligne (aucune connexion) :
    python3 misp_enrichir_evenement.py --offline misp_event_helios.json
  Simulation sur l'instance MISP :
    MISP_URL=https://localhost MISP_KEY=xxxx python3 misp_enrichir_evenement.py
  Application réelle :
    MISP_URL=https://localhost MISP_KEY=xxxx python3 misp_enrichir_evenement.py --apply

Prérequis : pip install pymisp ; clé d'API créée dans MISP (Administration > List Auth Keys).
Faire un export JSON de l'événement avant --apply, pour pouvoir revenir en arrière.
"""
import argparse, json, os, sys, re

EVENT_UUID = "1c56b296-c18e-4771-ba9b-e7ed7112f56f"
SOURCE = "Source : dossier SOC Helios (alertes SIEM, journaux, 02_indicateurs_40) - Collecté le 2026-10-06"

# --- UUID existants (relevés dans l'export de l'événement) -------------------------
OBJ = {
    "BIN-01": "1f603d83-d3c9-4631-90d4-430b5ccd2e4e",
    "BIN-02": "15d28b14-e261-45f0-86b6-72374445111f",
    "BIN-03": "00504c87-b03f-4ef3-88d1-4c699f2df7c4",
    "dom_livraison": "77017a65-3a93-41b3-b832-9bf33dfe5fcb",   # cdn-svc-update.test / 198.51.100.23
    "dom_c2": "0ef8cb11-14ae-46b4-98b6-0a7010f2880e",          # api-telemetry-eu.test / 198.51.100.24
    "dom_phishing": "9d962fa7-c9a5-4b1c-968a-121966503734",    # mail-secure-login.test / 198.51.100.40
}
ATT = {
    "c2_principal": "4f51dc52-f672-45f8-a6a7-44197a2a6cd3",    # 203.0.113.14
    "exfil": "5b45ecce-7861-4c13-b734-b7eea3141397",           # 203.0.113.28
    "url_bin02": "41ce6549-5f80-4d1f-9d3d-3c0a31457eb6",
    "url_beacon": "33670665-f34b-47ab-9edf-8a840022e861",
    "charge_ps": "4c9fd6ba-0952-497e-8c4e-29e153e60c58",
    "module_injecte": "59277f83-03e5-49ee-bfbe-a9ef192e6cc8",
    "archive": "2b1fe87a-e19f-4d52-96c4-ebeae5585072",
    "cert_c2": "9d527803-15cb-46c6-8abb-b071e6ab8328",         # sera remplacé par un objet x509
    "tache": "5953927c-06d6-4fae-a309-814e49b8b3c4",
    "cle_run": "34a5d0bb-250e-460a-a32f-7aadb0522149",
    "fichier_collecte": "6afcf22e-fb67-4349-88ac-3e1730b77f83",
    "compte_text": "33936dd5-425f-4663-b8f7-e324adceee2e",     # sera remplacé par un objet user-account
    "comptabilite07": "b0cffbb9-601b-4c63-9a2f-9593e572fe00",
    "url_owa": "641d5910-763f-45ae-800b-b38df143990e",
    "dom_usurpation": "794ef2fc-79bd-4518-9634-f1439dbb28fc",
    "url_leurre_rh": "acd04950-c324-4a74-831c-9a32d8cead14",
    "c2_repli": "18f4080f-eef5-4830-88e2-a74e3a1c8a30",        # 203.0.113.15
    "rdp_source": "709e2373-a33e-481d-8e93-230acb3587e1",      # 203.0.113.44
    "noeud_pdns": "70b95559-e098-4cec-ab2e-e59fd5a9fe5b",      # 198.51.100.61
    "cert_phishing": "1e30b824-1950-4357-bfef-6d13c9dfd90c",
    "dom_repli": "ba5227e5-566e-4dbf-851b-9f933ec3197f",       # static-assets-cache.test
}

# --- Nouveaux éléments ----------------------------------------------------------
NEW_TARGETS = [  # attributs target-machine : actifs de la victime cités par les alertes
    ("srv-fichiers-02", "Serveur de fichiers, RDP le 04/03 et injection (alertes 7, 8, 11)", "2026-03-04T01:47:00Z"),
    ("dc-01", "Contrôleur de domaine, LSASS, compte éphémère, exfiltration (alertes 5, 9, 10)", "2026-03-05T14:07:00Z"),
]
NEW_OBJECTS = {
    "x509_c2": ("x509", [("x509-fingerprint-sha1", "bda5d6c36e3ff362f9ce0957370a429fff58eb37"),
                         ("subject", "CN=update-service"), ("issuer", "CN=update-service"),
                         ("self_signed", "1")],
                "Certificat auto-signé partagé par les serveurs C2 - IoC n°33", "2026-03-02T09:20:00Z", ("b", "2")),
    "compte": ("user-account", [("username", "svc-backup-temp"),
                                ("description", "Compte de domaine créé le 05/03 14:10 et supprimé à 14:55 sur dc-01 ; utilisé en RDP le 04/03 01:47")],
               "Compte abusé par l'attaquant - IoC n°37, alertes 7 et 9", "2026-03-04T01:47:00Z", ("b", "2")),
}
# Remplacement des attributs isolés par les nouveaux objets
REPLACED = {"cert_c2": "x509_c2", "compte_text": "compte"}

# --- Relations : (source, relation, cible, commentaire) ---------------------------
# Les sources doivent être des objets ; les cibles peuvent être objets ou attributs.
RELATIONS = [
    ("BIN-01", "targets", "comptabilite07", "Ouvert sur le poste d'entrée (alerte 1)"),
    ("BIN-01", "drops", "charge_ps", "Charge PowerShell déchiffrée en mémoire"),
    ("BIN-01", "drops", "cle_run", "Persistance posée par BIN-01 (fiche BIN-01)"),
    ("BIN-01", "downloads", "url_bin02", "Téléchargement de la seconde charge (alerte 2)"),
    ("BIN-01", "downloads", "BIN-02", "BIN-01 récupère BIN-02"),
    ("BIN-02", "downloaded-from", "dom_livraison", "cdn-svc-update.test"),
    ("BIN-02", "communicates-with", "dom_c2", "Balise ~300 s (alerte 4)"),
    ("BIN-02", "communicates-with", "url_beacon", "Point de contact de la balise"),
    ("BIN-02", "communicates-with", "c2_principal", "Serveur de commande principal"),
    ("BIN-02", "communicates-with", "dom_repli", "Canal de repli (alerte 11)"),
    ("BIN-02", "communicates-with", "c2_repli", "Serveur de repli"),
    ("BIN-02", "drops", "tache", "Persistance par tâche planifiée (alerte 3)"),
    ("BIN-02", "drops", "module_injecte", "Module injecté dans explorer.exe (alerte 8)"),
    ("BIN-02", "targets", "comptabilite07", "Installé sur le poste d'entrée"),
    ("BIN-02", "targets", "T:srv-fichiers-02", "Module injecté sur le serveur de fichiers"),
    ("BIN-03", "targets", "T:dc-01", "Exécuté sur le contrôleur de domaine (alerte 5)"),
    ("BIN-03", "drops", "fichier_collecte", "Fichier de collecte avant chiffrement"),
    ("BIN-03", "drops", "archive", "Archive chiffrée avant exfiltration"),
    ("BIN-03", "exfiltrates-to", "exfil", "2,3 Gio en clair sur 8080 (alerte 10)"),
    ("dom_c2", "related-to", "c2_principal", "Hypothèse : redirecteur devant le serveur dorsal (supposée)"),
    ("dom_phishing", "uses", "cert_phishing", "Certificat de la page d'hameçonnage"),
    ("dom_phishing", "hosts", "url_owa", "Page de collecte d'identifiants"),
    ("dom_phishing", "related-to", "dom_usurpation", "Même phase d'hameçonnage, enregistrés le même matin"),
    ("x509_c2", "observed-on", "dom_c2", "Même certificat (IoC 33)"),
    ("x509_c2", "observed-on", "c2_principal", "Même certificat (IoC 33)"),
    ("x509_c2", "observed-on", "c2_repli", "Même certificat (IoC 33)"),
    ("x509_c2", "observed-on", "dom_repli", "Même certificat (IoC 16)"),
    ("compte", "authenticates-to", "T:srv-fichiers-02", "Session RDP 4624 type 10 (alerte 7)"),
    ("compte", "related-to", "T:dc-01", "Créé puis supprimé sur dc-01 (alerte 9)"),
    ("compte", "related-to", "rdp_source", "Source de la session RDP selon l'IoC 26 (contredit par l'alerte 7)"),
]

# --- Techniques ATT&CK observées et déduites (rapport tactique, section 4) --------
TECHNIQUES = [
    "T1583.001", "T1587.003", "T1566", "T1598.003", "T1204.002", "T1059.001", "T1053.005",
    "T1547.001", "T1136.002", "T1027", "T1564.003", "T1036.004", "T1036.005", "T1055",
    "T1070.001", "T1070", "T1003.001", "T1046", "T1021.001", "T1078.002", "T1570", "T1560",
    "T1074.001", "T1105", "T1071.001", "T1008", "T1048.003",
]

# ---------------------------------------------------------------------------------
def norm(v):
    v = v.strip().lower().replace("[.]", ".").replace("hxxp", "http")
    return v

def match_ioc(attr_value, iocs):
    a = norm(attr_value)
    for i in iocs:
        b = norm(i["valeur"])
        if a == b:
            return i
        # chemins et clés : comparaison sur le dernier élément
        if "\\" in a and "\\" in b and a.split("\\")[-1] == b.split("\\")[-1]:
            return i
    return None

def admiralty_tags(cote):
    return [f'admiralty-scale:source-reliability="{cote[0].lower()}"',
            f'admiralty-scale:information-credibility="{cote[1]}"']

def build_plan(event, iocs):
    plan = {"targets": [], "objects": [], "relations": [], "fixes": [], "delete": [], "techniques": TECHNIQUES}
    existing_values = {a["value"] for a in event.get("Attribute", [])}
    for name, comment, fs in NEW_TARGETS:
        if name not in existing_values:
            plan["targets"].append((name, comment, fs))
    obj_names = {(o["name"], o["Attribute"][0]["value"]) for o in event.get("Object", [])}
    for key, (tpl, attrs, comment, fs, cote) in NEW_OBJECTS.items():
        if (tpl, attrs[0][1]) not in obj_names:
            plan["objects"].append(key)
    existing_refs = set()
    for o in event.get("Object", []):
        for r in o.get("ObjectReference", []):
            existing_refs.add((o["uuid"], r.get("referenced_uuid"), r.get("relationship_type")))
    plan["relations"] = RELATIONS
    replaced_uuids = {ATT[k] for k in REPLACED}
    for a in event.get("Attribute", []):
        if a["uuid"] in replaced_uuids:
            continue
        i = match_ioc(a["value"], iocs)
        tags = [t["name"] for t in a.get("Tag", [])]
        need_fs = not a.get("first_seen") and i is not None
        need_tags = not any(t.startswith("admiralty-scale") for t in tags) and i is not None
        if need_fs or need_tags:
            plan["fixes"].append((a["uuid"], a["value"], i["premiere_vue"] if need_fs else None,
                                  i["confiance_admiralty"] if need_tags else None))
    for k in REPLACED:
        plan["delete"].append(ATT[k])
    return plan

def print_plan(plan):
    print(f"Nouveaux attributs cibles : {[t[0] for t in plan['targets']]}")
    print(f"Nouveaux objets : {plan['objects']}")
    print(f"Relations à créer : {len(plan['relations'])}")
    for s, rel, t, _ in plan["relations"]:
        print(f"   {s:14} --{rel}--> {t}")
    print(f"Attributs à compléter (first_seen / Admiralty) : {len(plan['fixes'])}")
    for u, v, fs, cote in plan["fixes"]:
        print(f"   {v[:45]:45} first_seen={fs}  admiralty={cote}")
    print(f"Attributs isolés remplacés par un objet puis supprimés (suppression douce) : {plan['delete']}")
    print(f"Techniques ATT&CK à attacher : {len(plan['techniques'])}")

def apply(plan, misp, event):
    from pymisp import MISPObject, MISPAttribute
    uuid_of = dict(OBJ); uuid_of.update(ATT)
    # 1. cibles
    for name, comment, fs in plan["targets"]:
        a = MISPAttribute(); a.type = "target-machine"; a.category = "Targeting data"; a.value = name
        a.to_ids = False; a.comment = f"{comment} - {SOURCE}"; a.first_seen = fs
        r = misp.add_attribute(event, a, pythonify=True)
        uuid_of[f"T:{name}"] = r.uuid
        for t in admiralty_tags("A1"): misp.tag(r, t)
        print("cible ajoutée", name)
    for a in misp.get_event(EVENT_UUID, pythonify=True).attributes:
        if a.type == "target-machine":
            uuid_of[f"T:{a.value}"] = a.uuid
    # 2. objets
    for key in plan["objects"]:
        tpl, attrs, comment, fs, cote = NEW_OBJECTS[key]
        o = MISPObject(tpl)
        for rel, val in attrs:
            o.add_attribute(rel, value=val)
        o.comment = f"{comment} - {SOURCE}"; o.first_seen = fs
        r = misp.add_object(event, o, pythonify=True)
        uuid_of[key] = r.uuid
        for at in r.attributes:
            for t in admiralty_tags(cote[0] + cote[1]): misp.tag(at, t)
        print("objet ajouté", key, r.uuid)
    ev = misp.get_event(EVENT_UUID, pythonify=True)
    for o in ev.objects:
        for key, (tpl, attrs, *_ ) in NEW_OBJECTS.items():
            if o.name == tpl and any(a.value == attrs[0][1] for a in o.attributes):
                uuid_of[key] = o.uuid
    # 3. relations
    objs = {o.uuid: o for o in ev.objects}
    done = {(o.uuid, r.referenced_uuid, r.relationship_type) for o in ev.objects for r in o.references}
    for s, rel, t, comment in plan["relations"]:
        su, tu = uuid_of.get(s), uuid_of.get(t)
        if not su or not tu or su not in objs:
            print("  relation ignorée (élément introuvable) :", s, rel, t); continue
        if (su, tu, rel) in done:
            continue
        ref = objs[su].add_reference(tu, rel, comment=comment)
        misp.add_object_reference(ref)
        print("  relation", s, rel, t)
    # 4. corrections
    for u, v, fs, cote in plan["fixes"]:
        a = misp.get_attribute(u, pythonify=True)
        if fs:
            a.first_seen = fs; misp.update_attribute(a)
        if cote:
            for t in admiralty_tags(cote): misp.tag(a, t)
        print("  corrigé", v[:40])
    # 5. suppression des doublons isolés
    for u in plan["delete"]:
        misp.delete_attribute(u)
    # 6. ATT&CK
    gal = [g for g in misp.galaxies(pythonify=True) if g.type == "mitre-attack-pattern"]
    if not gal:
        print("Galaxie mitre-attack-pattern absente : Galaxies > Update Galaxies, puis relancer."); return
    for tid in plan["techniques"]:
        clusters = misp.search_galaxy_clusters(gal[0], context="all", searchall=tid, pythonify=True)
        hit = [c for c in clusters if c.value.endswith(f"- {tid}")]
        if not hit:
            print("  technique introuvable :", tid); continue
        misp.tag(ev, hit[0].tag_name)
        print("  ATT&CK", hit[0].value)

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--offline", help="export JSON de l'événement, simulation sans connexion")
    ap.add_argument("--iocs", default="02_indicateurs_40.json")
    ap.add_argument("--apply", action="store_true")
    args = ap.parse_args()
    iocs = json.load(open(args.iocs, encoding="utf-8"))
    if args.offline:
        d = json.load(open(args.offline, encoding="utf-8"))
        event = d["response"][0]["Event"] if "response" in d else d.get("Event", d)
        print_plan(build_plan(event, iocs)); return
    from pymisp import PyMISP
    misp = PyMISP(os.environ["MISP_URL"], os.environ["MISP_KEY"], ssl=False)
    ev = misp.get_event(EVENT_UUID, pythonify=True)
    event_dict = ev.to_dict()
    plan = build_plan(event_dict, iocs)
    print_plan(plan)
    if not args.apply:
        print("\nSimulation uniquement. Relancer avec --apply pour écrire dans MISP."); return
    apply(plan, misp, ev)
    print("\nTerminé. Vérifier l'événement dans MISP, puis exporter en STIX 2.1.")

if __name__ == "__main__":
    main()
