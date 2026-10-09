"""Régénère les PDF : python build.py  (nécessite pandoc et playwright)."""
import subprocess, pathlib, sys
from playwright.sync_api import sync_playwright
here = pathlib.Path(__file__).resolve().parent
root = here.parent.parent
jobs = [  # (source md, pdf, classe css, titre, pied de page)
    (root/"rapports/rapport_tactique_SOC.md", root/"rapports/rapport_tactique_SOC.pdf", "", "Rapport tactique INC-2026-0302", True),
    (root/"rapports/rapport_strategique_direction.md", root/"rapports/rapport_strategique_direction.pdf", "strat", "Synthèse direction INC-2026-0302", True),
    (root/"notes/06_note_ANSSI.md", root/"notes/06_note_ANSSI.pdf", "note1", "Note réglementaire ANSSI", False),
    (root/"notes/07_note_partage_TLP.md", root/"notes/07_note_partage_TLP.pdf", "note1", "Note de partage TLP", False),
]
css = (here/"style.css").read_text(encoding="utf-8")
with sync_playwright() as p:
    b = p.chromium.launch(); 
    for src, pdf, cls, title, footer in jobs:
        frag = subprocess.run(["pandoc", "-f", "markdown-smart", "-t", "html", "--no-highlight", "--columns=100000", str(src)], capture_output=True, text=True, check=True).stdout
        html = f'<!doctype html><html lang="fr"><head><meta charset="utf-8"><title>{title}</title><style>{css}</style></head><body class="{cls}">{frag}</body></html>'
        tmp = src.parent/("_tmp_"+src.stem+".html"); tmp.write_text(html, encoding="utf-8")
        page = b.new_page(); page.goto(tmp.as_uri()); page.wait_for_load_state("networkidle")
        ft = f'<div style="font-size:7pt;color:#6b7785;width:100%;padding:0 16mm;display:flex;justify-content:space-between;font-family:sans-serif"><span>TLP:AMBER · {title}</span><span><span class="pageNumber"></span> / <span class="totalPages"></span></span></div>'
        page.pdf(path=str(pdf), format="A4", print_background=True, 
                 display_header_footer=footer, header_template="<span></span>", footer_template=ft,
                 margin=({"top":"18mm","bottom":"18mm","left":"16mm","right":"16mm"} if footer else {"top":"12mm","bottom":"11mm","left":"14mm","right":"14mm"}))
        page.close(); tmp.unlink(); print("ok", pdf.name)
    b.close()
