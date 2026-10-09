import sys, matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
from matplotlib import font_manager as fm
out = sys.argv[1]
plt.rcParams["font.family"] = "Inter" if any("Inter" in f.name for f in fm.fontManager.ttflist) else "DejaVu Sans"
NAVY, BLUE, RED, GREY = "#0f2a43", "#1d4e7a", "#b3261e", "#6b7785"

def draw(path, lanes, events, note):
    fig, ax = plt.subplots(figsize=(9.2, 3.25), dpi=200)
    for i, name in enumerate(lanes):
        y = len(lanes) - 1 - i
        ax.hlines(y, 1.75, 7.6, color="#d5dde6", lw=7, zorder=1, capstyle="round")
        ax.text(1.68, y, name, ha="right", va="center", fontsize=8.6, color=NAVY, fontweight="bold")
    for day, lane, label, color, dy in events:
        y = len(lanes) - 1 - lane
        ax.scatter([day], [y], s=95, color=color, zorder=3, edgecolor="white", linewidth=1.2)
        ax.annotate(label, (day, y), xytext=(0, 13 * dy), textcoords="offset points", ha="center",
                    va="bottom" if dy > 0 else "top", fontsize=7.4, color="#1c2430", linespacing=1.25)
    for d in range(2, 8):
        ax.axvline(d, color="#e7ecf1", lw=0.8, zorder=0)
        ax.text(d, -0.78, f"{d} mars", ha="center", va="top", fontsize=8, color=GREY)
    ax.text(7.6, len(lanes) - 0.25, note, ha="right", va="bottom", fontsize=7.2, color=RED, style="italic")
    ax.set_xlim(0.2, 7.75); ax.set_ylim(-1.0, len(lanes) - 0.1); ax.axis("off")
    fig.tight_layout(pad=0.3); fig.savefig(path, facecolor="white"); plt.close(fig)

draw(f"{out}/chronologie.png",
     ["comptabilite-07", "srv-fichiers-02", "dc-01"],
     [(2.0, 0, "Macro, balise,\npersistance (A1 à A4)", BLUE, 1),
      (3.0, 0, "Balayage réseau (A6)", BLUE, -1),
      (7.0, 0, "Effacement des\njournaux (A12)", RED, 1),
      (4.0, 1, "RDP de nuit puis\nimplant (A7, A8)", BLUE, 1),
      (6.0, 1, "Canal de repli (A11)", RED, -1),
      (5.0, 2, "LSASS, compte éphémère,\nexfiltration 2,3 Go (A5, A9, A10)", RED, 1)],
     "En rouge : étapes critiques ou postérieures à la détection")
draw(f"{out}/chronologie_direction.png",
     ["Poste comptabilité", "Serveur de fichiers", "Serveur des comptes"],
     [(2.0, 0, "Fausse facture ouverte,\nlogiciel espion installé", BLUE, 1),
      (3.0, 0, "Exploration du réseau", BLUE, -1),
      (7.0, 0, "Effacement\nde traces", RED, 1),
      (4.0, 1, "Connexion de nuit,\nprise de contrôle", BLUE, 1),
      (6.0, 1, "Changement de canal", RED, -1),
      (5.0, 2, "Vol de mots de passe,\n2,3 Go sortis", RED, 1)],
     "En rouge : étapes critiques ou postérieures à la détection")
