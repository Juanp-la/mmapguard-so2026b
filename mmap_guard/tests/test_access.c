// SPDX-License-Identifier: GPL-2.0
/**
 * @file test_access.c
 * @brief Cliente de prueba del "camino feliz" autorizado de MMAPGuard.
 * @course Sistemas Operativos - SO2026B (EAFIT)
 *
 * Demuestra:
 *   1. mmap() aceptado para el uid autorizado.
 *   2. Lectura con descifrado transparente por page fault (el contenido llega
 *      en claro al proceso autorizado).
 *   3. Escritura en MAP_SHARED (interceptada por page_mkwrite).
 *   4. Consulta de estadísticas y verificación de integridad vía ioctl.
 *
 * Uso:  ./test_access
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/mman.h>
#include <sys/ioctl.h>
#include "../kernel/mmapguard_uapi.h"

#define DEV   "/dev/mmapguard"
#define PGSZ  4096

static void dump_stats(int fd)
{
	struct mg_stats st;

	if (ioctl(fd, MG_IOC_GET_STATS, &st) != 0) {
		perror("ioctl GET_STATS");
		return;
	}
	printf("\n--- Estadisticas MMAPGuard ---\n");
	printf("  uid_autorizado : %u\n", st.authorized_uid);
	printf("  solo_lectura   : %u\n", st.readonly);
	printf("  integridad_ok  : %u (crc_ref=0x%08x crc_vivo=0x%08x)\n",
	       st.integrity_ok, st.plain_crc, st.live_crc);
	printf("  OPEN=%llu MMAP_OK=%llu MMAP_DENY=%llu FAULT=%llu\n",
	       (unsigned long long)st.counters[0], (unsigned long long)st.counters[1],
	       (unsigned long long)st.counters[2], (unsigned long long)st.counters[3]);
	printf("  MKWRITE_OK=%llu MKWRITE_DENY=%llu SYNC=%llu INTEGRITY_BAD=%llu\n",
	       (unsigned long long)st.counters[4], (unsigned long long)st.counters[5],
	       (unsigned long long)st.counters[6], (unsigned long long)st.counters[7]);
}

int main(void)
{
	int fd;
	char *map;

	printf("[test_access] uid efectivo = %d\n", (int)geteuid());

	fd = open(DEV, O_RDWR);
	if (fd < 0) {
		perror("open " DEV);
		fprintf(stderr, "Sugerencia: cargue el modulo y 'chmod 666 %s'.\n", DEV);
		return 1;
	}

	/* Mapeo compartido lectura/escritura. */
	map = mmap(NULL, PGSZ * 2, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
	if (map == MAP_FAILED) {
		perror("mmap");
		close(fd);
		return 1;
	}
	printf("[test_access] mmap OK en %p\n", (void *)map);

	/* Lectura: dispara page fault -> descifrado transparente. */
	printf("[test_access] Pagina 0 (en claro):\n    %.72s\n", map);

	/* Escritura: dispara page_mkwrite (auditada). */
	printf("[test_access] Escribiendo marca en la pagina 0...\n");
	snprintf(map, 64, "[MODIFICADO POR uid=%d pid=%d]\n", (int)geteuid(), (int)getpid());
	printf("[test_access] Marca escrita en el mapeo (se recifrara al cerrar el VMA).\n");

	dump_stats(fd);

	/* El recifrado y la actualizacion del contenido ocurren al cerrar el VMA
	 * (munmap). Por eso, ANTES del munmap, el baseline sigue intacto. */
	printf("\n[test_access] ioctl CHECK (antes de cerrar el mapeo): ");
	if (ioctl(fd, MG_IOC_CHECK, 0) == 0)
		printf("integridad intacta (el cambio se consolida al munmap)\n");
	else
		printf("ALTERACION DETECTADA\n");

	munmap(map, PGSZ * 2);
	close(fd);
	printf("[test_access] Mapeo cerrado: contenido recifrado en el almacen.\n");
	return 0;
}
