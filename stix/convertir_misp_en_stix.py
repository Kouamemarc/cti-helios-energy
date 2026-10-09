#!/usr/bin/env python3
"""Convertit la sauvegarde JSON d'un événement MISP en bundle STIX 2.1.

Usage :  python stix/convertir_misp_en_stix.py stix/misp_event_helios.json stix/misp_export_stix2.json
Dépendance : pip install misp-stix

Utilise misp-stix, le convertisseur officiel du projet MISP : c'est la bibliothèque que
MISP appelle lui-même pour son export « STIX 2 ». Ce script sert quand cet export
échoue dans l'interface (erreur interne), le résultat est le même.
"""
import copy
import json
import sys

from misp_stix_converter import MISPtoSTIX21Parser


def reporter_cotes(event, bundle):
    """Dans MISP, la cote Admiralty est posée sur chaque attribut. Pour un objet (fichier,
    couple domaine-adresse), la conversion ne la reporte pas sur l'objet STIX : on la recopie
    ici, en prenant la cote du SHA-256 pour un fichier, sinon celle du premier attribut coté."""
    for obj in event.get("Object", []):
        attrs = sorted(obj.get("Attribute", []), key=lambda a: a["type"] != "sha256")
        cote = next(([t["name"] for t in a.get("Tag", []) if t["name"].startswith("admiralty-scale:")]
                     for a in attrs if any(t["name"].startswith("admiralty-scale:") for t in a.get("Tag", []))), [])
        for o in bundle["objects"]:
            if o["id"].endswith(obj["uuid"]) and o["type"] in ("indicator", "observed-data"):
                o["labels"] = list(dict.fromkeys(o.get("labels", []) + sorted(cote, reverse=True)))


def main(src, dst):
    data = json.load(open(src, encoding="utf-8"))
    if "response" in data:          # forme « Download as MISP JSON »
        data = data["response"][0]
    original = copy.deepcopy(data)   # le convertisseur modifie l'événement qu'on lui passe
    parser = MISPtoSTIX21Parser()
    parser.parse_misp_event(data)
    bundle = json.loads(parser.bundle.serialize())
    reporter_cotes(original["Event"], bundle)
    json.dump(bundle, open(dst, "w", encoding="utf-8"), ensure_ascii=False, indent=2)
    types = {}
    for o in bundle["objects"]:
        types[o["type"]] = types.get(o["type"], 0) + 1
    print(f"Bundle écrit : {dst}  ({len(bundle['objects'])} objets)")
    print("  ", dict(sorted(types.items())))
    for uuid, msgs in dict(getattr(parser, "errors", {})).items():
        print("  ERREURS :", sorted(set(msgs)))
    for uuid, msgs in dict(getattr(parser, "warnings", {})).items():
        print("  avertissements :", sorted(set(msgs)))


if __name__ == "__main__":
    if len(sys.argv) != 3:
        sys.exit(__doc__)
    main(sys.argv[1], sys.argv[2])
