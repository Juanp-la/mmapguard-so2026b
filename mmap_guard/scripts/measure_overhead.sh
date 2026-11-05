#!/usr/bin/env bash
# ==============================================================================
# measure_overhead.sh - Medición del sobrecosto con strace/perf/ftrace
# Cuantifica el impacto de MMAPGuard en syscalls y page faults.
# REQUIERE el módulo cargado (sudo ./scripts/run_demo.sh deja el entorno listo,
# o cargue manualmente con: sudo make -C kernel load).
# ==============================================================================
set -u
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
BIN="$HERE/tests/bench"

[ -x "$BIN" ] || make -C "$HERE/tests" >/dev/null

echo "=== 1) Latencia y fallos de pagina (getrusage) ==="
"$BIN" 3000

echo; echo "=== 2) Conteo de syscalls con strace (resumen -c) ==="
if command -v strace >/dev/null; then
	strace -f -c -e trace=mmap,munmap,madvise "$BIN" 500 2>&1 | tail -20
else
	echo "strace no instalado (sudo apt-get install strace)"
fi

echo; echo "=== 3) perf stat: fallos de pagina y ciclos ==="
if command -v perf >/dev/null; then
	perf stat -e page-faults,minor-faults,cycles,instructions "$BIN" 2000 2>&1 | tail -15
else
	echo "perf no instalado (sudo apt-get install linux-tools-common linux-tools-\$(uname -r))"
fi

echo; echo "=== 4) ftrace: traza de la funcion .fault del modulo (opcional) ==="
echo "Sugerencia (root):"
echo "  echo mg_vma_fault > /sys/kernel/debug/tracing/set_ftrace_filter"
echo "  echo function > /sys/kernel/debug/tracing/current_tracer"
echo "  cat /sys/kernel/debug/tracing/trace_pipe   # mientras corre ./tests/bench"
