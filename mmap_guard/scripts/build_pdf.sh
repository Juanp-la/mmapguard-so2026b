#!/usr/bin/env bash
# Genera INFORME.pdf a partir de INFORME.md con el estilo del curso.
# Requiere: pandoc, wkhtmltopdf, xvfb
#   sudo apt-get install -y pandoc wkhtmltopdf xvfb
set -e
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$HERE"
TMP="$(mktemp -d)"
pandoc scripts/informe.meta.yaml INFORME.md -f markdown -t html5 -s \
  --css scripts/informe.css --embed-resources --standalone \
  --toc -V toc-title="Contenido" --highlight-style=tango \
  -o "$TMP/informe.html"
xvfb-run -a wkhtmltopdf --enable-local-file-access --print-media-type \
  --margin-top 15mm --margin-bottom 15mm --margin-left 15mm --margin-right 15mm \
  "$TMP/informe.html" INFORME.pdf
rm -rf "$TMP"
echo "[+] INFORME.pdf generado."
