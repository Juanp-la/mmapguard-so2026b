#!/usr/bin/env bash
# ==============================================================================
# run_demo.sh - Demostración guiada de MMAPGuard (SO2026B - EAFIT)
# Carga el módulo, ejecuta los escenarios de defensa y vuelca la auditoría.
# REQUIERE root (insmod/rmmod). Ejecutar: sudo ./scripts/run_demo.sh
# ==============================================================================
set -u
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
KDIR_DEFAULT="/lib/modules/$(uname -r)/build"
KDIR="${KDIR:-$KDIR_DEFAULT}"

C_OK='\033[0;32m'; C_WARN='\033[1;33m'; C_INFO='\033[0;36m'; C_ERR='\033[0;31m'; NC='\033[0m'
say()  { echo -e "${C_INFO}==>${NC} $*"; }
ok()   { echo -e "${C_OK}[OK]${NC} $*"; }
warn() { echo -e "${C_WARN}[!]${NC} $*"; }

if [ "$(id -u)" -ne 0 ]; then
	echo -e "${C_ERR}Debe ejecutarse como root (sudo).${NC}"; exit 1
fi

cleanup() { rmmod mmapguard 2>/dev/null || true; }
trap cleanup EXIT

say "Compilando modulo y pruebas..."
make -C "$HERE/kernel" KDIR="$KDIR" modules >/dev/null || { echo "fallo build modulo"; exit 1; }
make -C "$HERE/tests" >/dev/null || { echo "fallo build tests"; exit 1; }
ok "Compilacion completa."

# ------------------------------------------------------------------ Escenario 1
echo; say "ESCENARIO 1 — Lectura/escritura AUTORIZADA (readonly=0, uid autorizado=root)"
rmmod mmapguard 2>/dev/null || true
insmod "$HERE/kernel/mmapguard.ko" authorized_uid=0 readonly=0
chmod 666 /dev/mmapguard
"$HERE/tests/test_access"
ok "Escenario 1 completado."

# ------------------------------------------------------------------ Escenario 2
echo; say "ESCENARIO 2 — Acceso de un uid NO autorizado (se espera EACCES)"
# El modulo queda cargado con authorized_uid=0; 'nobody' debe ser rechazado.
# Se copia el binario a /tmp (ejecutable por cualquiera) para que el rechazo
# provenga del MODULO al hacer mmap, y no de permisos de ejecucion en /home.
if id nobody >/dev/null 2>&1; then
	install -m 0755 "$HERE/tests/test_access" /tmp/mg_test_access
	if sudo -u nobody /tmp/mg_test_access; then
		warn "El proceso no autorizado NO fue rechazado (revisar politica)."
	else
		ok "Rechazo confirmado: el modulo denego mmap al uid no autorizado (EACCES)."
	fi
	rm -f /tmp/mg_test_access
else
	warn "Usuario 'nobody' no disponible; omitiendo."
fi

# ------------------------------------------------------------------ Escenario 3
echo; say "ESCENARIO 3 — Politica de SOLO LECTURA + evasion mprotect (readonly=1)"
rmmod mmapguard 2>/dev/null || true
insmod "$HERE/kernel/mmapguard.ko" authorized_uid=0 readonly=1
chmod 666 /dev/mmapguard
"$HERE/tests/test_readonly"
ok "Escenario 3 completado."

# ------------------------------------------------------------------ Escenario 4
echo; say "ESCENARIO 4 — Concurrencia (madvise MADV_DONTNEED + lecturas)"
rmmod mmapguard 2>/dev/null || true
insmod "$HERE/kernel/mmapguard.ko" authorized_uid=0 readonly=0
chmod 666 /dev/mmapguard
"$HERE/tests/test_race" 1500
ok "Escenario 4 completado."

# ------------------------------------------------------------------ Escenario 5
echo; say "ESCENARIO 5 — Sobrecosto (benchmark ruta protegida vs anonima)"
"$HERE/tests/bench" 2000

# ------------------------------------------------------------------ Auditoria
echo; say "REGISTRO DE AUDITORIA (/proc/mmapguard)"
cat /proc/mmapguard

echo; ok "Demostracion finalizada. Descargando modulo..."
