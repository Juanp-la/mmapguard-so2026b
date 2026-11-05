# ==============================================================================
# Makefile del módulo de kernel MMAPGuard (SO2026B - EAFIT)
# Compila un único .ko a partir de tres objetos (core + crypto + audit).
# Objetivo de la rúbrica: "clean build" sin advertencias.
# ==============================================================================

# Nombre del módulo resultante: mmapguard.ko
obj-m += mmapguard.o
mmapguard-objs := mg_core.o mg_crypto.o mg_audit.o

# Advertencias estrictas para el código del módulo.
ccflags-y := -Wall

# Directorio de headers del kernel en ejecución (sobre-escribible: KDIR=...).
KDIR ?= /lib/modules/$(shell uname -r)/build
PWD  := $(shell pwd)

.PHONY: all modules clean load unload reload status

all: modules

modules:
	$(MAKE) -C $(KDIR) M=$(PWD) modules

clean:
	$(MAKE) -C $(KDIR) M=$(PWD) clean

# --- Ayudas de ejecución (requieren privilegios de root) ----------------------
# Parámetros por defecto configurables: make load UID=1000 RO=0
UID ?= 0
RO  ?= 0

load: modules
	sudo insmod mmapguard.ko authorized_uid=$(UID) readonly=$(RO)
	sudo chmod 666 /dev/mmapguard
	@echo "[+] Cargado. uid_autorizado=$(UID) readonly=$(RO)"

unload:
	-sudo rmmod mmapguard
	@echo "[+] Descargado."

reload: unload load

status:
	@lsmod | grep mmapguard || echo "mmapguard no esta cargado"
	@echo "--- /proc/mmapguard ---"
	@cat /proc/mmapguard 2>/dev/null || echo "(dispositivo no disponible)"
