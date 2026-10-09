#!/usr/bin/env python3
"""Dessine le graphe du renseignement à partir du bundle STIX 2.1.

Usage :  python graphe/generer_graphe.py stix/bundle_helios.json graphe/graphe_helios.png
Dépendances : pip install networkx matplotlib

Lecture du graphe : l'acteur en haut, ses outils au centre, les techniques ATT&CK à
gauche, les indicateurs à droite. Dans l'export MISP, un même indice existe sous
plusieurs formes (indicateur, observation, observable) : elles sont fusionnées en un
seul nœud pour que le graphe reste lisible.
"""
import json
import sys
from collections import defaultdict

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import networkx as nx
from matplotlib.lines import Line2D

IGNORES = {"marking-definition", "grouping", "report", "relationship", "note", "opinion"}
STYLE = {  # catégorie : (libellé, couleur)
    "acteur": ("Acteur ou cluster", "#b3261e"),
    "victime": ("Victime", "#6b4e9b"),
    "outil": ("Outil de l'attaquant", "#d9822b"),
    "technique": ("Technique ATT&CK", "#1d4e7a"),
    "reseau": ("Indicateur réseau", "#2e8b6f"),
    "hote": ("Indicateur fichier ou système", "#7a8793"),
}
RESEAU = {"domain-name", "ipv4-addr", "ipv6-addr", "url", "network-traffic", "x509-certificate"}
FR = {"uses": "utilise", "indicates": "indique", "targets": "vise", "drops": "dépose", "related-to": "lié à",
      "communicates-with": "communique avec", "downloaded-from": "téléchargé depuis", "creates": "crée",
      "executes": "exécute", "exfiltrates-to": "exfiltre vers", "hosts": "héberge"}


def court(txt, n=38):
    txt = str(txt)
    return txt if len(txt) <= n else txt[: n - 1] + "…"


def charger(chemin):
    objs = json.load(open(chemin, encoding="utf-8"))["objects"]
    by_id = {o["id"]: o for o in objs}
    createurs = {o.get("created_by_ref") for o in objs}

    # Fusion : indicateur + observation + observables d'un même indice -> un seul nœud
    parent = {}

    def racine(x):
        while parent.get(x, x) != x:
            x = parent[x]
        return x

    def unir(a, b):
        parent[racine(a)] = racine(b)

    par_uuid = defaultdict(list)
    for o in objs:
        if o["type"] in ("indicator", "observed-data") or "created" not in o:
            par_uuid[o["id"].split("--", 1)[1]].append(o["id"])
    for groupe in par_uuid.values():
        for i in groupe[1:]:
            unir(groupe[0], i)
    for o in objs:
        if o["type"] == "observed-data":
            for ref in o.get("object_refs", []):
                unir(o["id"], ref)
        if o["type"] == "relationship" and o["relationship_type"] == "based-on":
            unir(o["source_ref"], o["target_ref"])

    membres = defaultdict(list)
    for o in objs:
        if o["type"] not in IGNORES and o["id"] not in createurs:
            membres[racine(o["id"])].append(o)

    G = nx.DiGraph()
    for r, groupe in membres.items():
        types = {o["type"] for o in groupe}
        cat, nom = "hote", None
        if types & {"intrusion-set", "threat-actor"}:
            cat, nom = "acteur", next(o["name"] for o in groupe if "name" in o)
        elif "identity" in types:
            cat, nom = "victime", groupe[0].get("name")
        elif types & {"malware", "tool"}:
            cat, nom = "outil", groupe[0].get("name")
        elif "attack-pattern" in types:
            o = groupe[0]
            tid = next((x["external_id"] for x in o.get("external_references", []) if x.get("external_id")), "")
            cat, nom = "technique", f"{tid} {o.get('name', '').split(': ')[-1]}".strip()
        else:
            if types & RESEAU:
                cat = "reseau"
            vals = []
            for o in groupe:  # la valeur la plus parlante en premier
                if o["type"] == "file" and o.get("name"):
                    vals.insert(0, o["name"])
                elif o["type"] in ("domain-name", "url"):
                    vals.insert(0, o["value"])
                elif o["type"] in ("ipv4-addr", "ipv6-addr"):
                    vals.append(o["value"])
                elif o["type"] == "file" and o.get("hashes"):
                    vals.append("sha256 " + next(iter(o["hashes"].values()))[:12] + "…")
                elif o["type"] == "x509-certificate":
                    vals.append("certificat " + next(iter(o.get("hashes", {"": "?"}).values()))[:10] + "…")
                elif o["type"] == "windows-registry-key":
                    vals.append("…\\" + "\\".join(o["key"].split("\\")[-2:]))
                elif o.get("x_misp_value"):
                    vals.append(o["x_misp_value"])
            vals = list(dict.fromkeys(vals))
            nom = " · ".join(vals[:2]) if vals else groupe[0]["type"]
        G.add_node(r, cat=cat, label=court(nom, 44 if cat == "technique" else 40))

    for o in objs:
        if o["type"] == "relationship" and o["relationship_type"] != "based-on":
            a, b = racine(o["source_ref"]), racine(o["target_ref"])
            if a in G and b in G and a != b:
                G.add_edge(a, b, kind=o["relationship_type"])
    return G


def disposer(G):
    """Colonnes : techniques | outils | indicateurs reliés | indicateurs isolés ; acteurs en haut."""
    cat = nx.get_node_attributes(G, "cat")
    U = G.to_undirected()
    outils = sorted((n for n in G if cat[n] == "outil"), key=lambda n: G.nodes[n]["label"])
    pos, hauteur = {}, 30.0

    def colonne(noeuds, x, haut=hauteur, bas=0.0):
        pas = (haut - bas) / max(len(noeuds), 1)
        for i, n in enumerate(noeuds):
            pos[n] = (x, haut - pas * (i + 0.5))

    def rang(n):  # range un nœud près de l'outil auquel il est rattaché
        d = [nx.shortest_path_length(U, n, o) if nx.has_path(U, n, o) else 99 for o in outils] or [99]
        return (d.index(min(d)), min(d), G.nodes[n]["label"])

    colonne(outils, 0.0, hauteur * 0.78, hauteur * 0.12)
    colonne(sorted((n for n in G if cat[n] == "technique"), key=rang), -1.5)
    indic = [n for n in G if cat[n] in ("reseau", "hote")]
    # pivots : indices rattachés directement à un outil par une relation « indique »
    pivots = sorted((n for n in indic if any(cat[v] == "outil" and d["kind"] == "indicates" for _, v, d in G.out_edges(n, data=True))), key=rang)
    lies = sorted((n for n in indic if n not in pivots and U.degree(n) > 0), key=rang)
    seuls = sorted((n for n in indic if U.degree(n) == 0), key=lambda n: G.nodes[n]["label"])
    colonne(pivots, 1.0, hauteur * 0.78, hauteur * 0.12)
    moitie = (len(lies) + 1) // 2 if len(lies) > 14 else len(lies)
    colonne(lies[:moitie], 2.2)
    if lies[moitie:]:
        colonne(lies[moitie:], 3.3)
    colonne(seuls, 4.5)
    acteurs = sorted((n for n in G if cat[n] == "acteur"), key=lambda n: -U.degree(n))
    for i, n in enumerate(acteurs):
        pos[n] = (0.0 - 0.85 * i, hauteur + 2.2 + (0.0 if i == 0 else 1.0))
    for i, n in enumerate(n for n in G if cat[n] == "victime"):
        pos[n] = (1.0 + 0.6 * i, hauteur + 2.2)
    return pos, bool(seuls)


def dessiner(G, sortie):
    pos, a_isoles = disposer(G)
    cat = nx.get_node_attributes(G, "cat")
    fig, ax = plt.subplots(figsize=(20, 12.5), dpi=150)
    for a, b, d in G.edges(data=True):
        cats = {cat[a], cat[b]}
        coul = "#b3261e" if "acteur" in cats else "#1d4e7a" if "technique" in cats else "#d9822b" if "outil" in cats else "#9aa5b1"
        ax.annotate("", xy=pos[b], xytext=pos[a],
                    arrowprops=dict(arrowstyle="-|>", color=coul, lw=0.9, alpha=0.55, shrinkA=7, shrinkB=7,
                                    connectionstyle="arc3,rad=0.06"))
        if cats <= {"acteur", "outil", "victime"} or (cats <= {"reseau", "hote", "outil"} and d["kind"] not in ("indicates", "related-to")):
            xm, ym = (pos[a][0] * 0.55 + pos[b][0] * 0.45), (pos[a][1] * 0.55 + pos[b][1] * 0.45)
            txt = "recouvrement partiel" if cats == {"acteur"} else FR.get(d["kind"], d["kind"])
            ax.text(xm, ym, txt, fontsize=5.8, color=coul, ha="center", va="center",
                    bbox=dict(boxstyle="round,pad=0.12", fc="white", ec="none", alpha=0.85))
    for n, (x, y) in pos.items():
        c = cat[n]
        gros = c in ("acteur", "outil", "victime")
        ax.scatter([x], [y], s=330 if gros else 85, color=STYLE[c][1], edgecolor="white", linewidth=1.2, zorder=3)
        if c == "technique":
            ax.text(x - 0.05, y, G.nodes[n]["label"], ha="right", va="center", fontsize=7.2, color="#1c2430")
        elif gros:
            ax.text(x, y + 0.75, G.nodes[n]["label"], ha="center", va="bottom", fontsize=8.6, fontweight="bold", color="#1c2430",
                    bbox=dict(boxstyle="round,pad=0.15", fc="white", ec="none", alpha=0.85), zorder=4)
        else:
            ax.text(x + 0.05, y, G.nodes[n]["label"], ha="left", va="center", fontsize=7.0, color="#1c2430")
    xs = [p[0] for p in pos.values()]
    if a_isoles:
        ax.text(4.5, 30.6, "Indicateurs non reliés\n(à corroborer ou écartés)", ha="left", va="bottom", fontsize=7.5,
                color="#6b7785", style="italic")
    ax.legend(handles=[Line2D([0], [0], marker="o", ls="", color=v[1], label=v[0], markersize=8) for v in STYLE.values()],
              loc="lower left", fontsize=8, frameon=False, ncol=3, bbox_to_anchor=(0.0, -0.035))
    nb_rel = G.number_of_edges()
    ax.set_title(f"Graphe du renseignement, INC-2026-0302 · {G.number_of_nodes()} nœuds, {nb_rel} relations · TLP:AMBER",
                 fontsize=11, loc="left", color="#0f2a43", pad=10)
    ax.set_xlim(min(xs) - 2.3, max(xs) + 1.9)
    ax.set_ylim(-1.2, 35.5)
    ax.axis("off")
    fig.tight_layout()
    fig.savefig(sortie, facecolor="white")
    if sortie.lower().endswith(".png"):
        fig.savefig(sortie[:-4] + ".pdf", facecolor="white")
    print(f"Graphe écrit : {sortie}  ({G.number_of_nodes()} nœuds, {nb_rel} relations)")
    from collections import Counter
    print("  ", dict(Counter(cat.values())))


if __name__ == "__main__":
    if len(sys.argv) != 3:
        sys.exit(__doc__)
    dessiner(charger(sys.argv[1]), sys.argv[2])
