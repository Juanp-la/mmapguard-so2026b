// SPDX-License-Identifier: GPL-2.0
/**
 * @file test_readonly.c
 * @brief Verifica la política de solo lectura y la mitigación de la evasión
 *        O_RDONLY + mprotect(PROT_WRITE).
 * @course Sistemas Operativos - SO2026B (EAFIT)
 *
 * Escenario (el módulo debe estar cargado con readonly=1):
 *   A. mmap con PROT_WRITE  -> debe FALLAR con EACCES (rechazado en dev_mmap).
 *   B. mmap con PROT_READ   -> debe funcionar (lectura descifrada).
 *   C. mprotect(PROT_WRITE) sobre el mapeo de solo lectura -> debe FALLAR,
 *      porque el kernel limpió VM_MAYWRITE del VMA.
 *
 * Uso:  ./test_readonly
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/mman.h>

#define DEV   "/dev/mmapguard"
#define PGSZ  4096

int main(void)
{
	int fd, fails = 0;
	char *ro;

	fd = open(DEV, O_RDWR);
	if (fd < 0) {
		perror("open " DEV);
		return 1;
	}

	/* A. Intento de mapeo escribible: se espera EACCES. */
	printf("[A] mmap(PROT_READ|PROT_WRITE) sobre region RO... ");
	char *rw = mmap(NULL, PGSZ, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
	if (rw == MAP_FAILED) {
		printf("RECHAZADO (errno=%d %s) [OK, esperado]\n", errno, strerror(errno));
	} else {
		printf("ACEPTADO [FALLA: no deberia permitirse]\n");
		fails++;
		munmap(rw, PGSZ);
	}

	/* B. Mapeo de solo lectura: debe funcionar. */
	printf("[B] mmap(PROT_READ) sobre region RO... ");
	ro = mmap(NULL, PGSZ, PROT_READ, MAP_SHARED, fd, 0);
	if (ro == MAP_FAILED) {
		printf("FALLO (errno=%d) [FALLA: deberia permitirse]\n", errno);
		close(fd);
		return 1;
	}
	printf("OK -> contenido: %.48s\n", ro);

	/* C. Escalada por mprotect: se espera que falle. */
	printf("[C] mprotect(PROT_WRITE) para escalar a escribible... ");
	if (mprotect(ro, PGSZ, PROT_READ | PROT_WRITE) != 0) {
		printf("RECHAZADO (errno=%d %s) [OK, mitigacion efectiva]\n",
		       errno, strerror(errno));
	} else {
		printf("PERMITIDO [FALLA: evasion no mitigada]\n");
		fails++;
	}

	munmap(ro, PGSZ);
	close(fd);

	printf("\n[resultado] %s\n", fails == 0 ?
	       "TODAS las comprobaciones de solo lectura pasaron." :
	       "Hubo comprobaciones fallidas.");
	return fails == 0 ? 0 : 1;
}
