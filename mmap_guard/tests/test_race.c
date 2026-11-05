// SPDX-License-Identifier: GPL-2.0
/**
 * @file test_race.c
 * @brief Prueba de concurrencia: expulsa páginas con madvise(MADV_DONTNEED)
 *        mientras otro hilo lee, para evidenciar que la materialización
 *        descifrada es consistente bajo carrera (el store_lock del kernel
 *        serializa el descifrado; nunca se observan bytes a medio descifrar).
 * @course Sistemas Operativos - SO2026B (EAFIT)
 *
 * Esta prueba NO es un exploit: es una verificación defensiva de que el camino
 * .fault del módulo no sufre condiciones de carrera que entreguen contenido
 * corrupto. Si la defensa fuese incorrecta, veríamos páginas con bytes mezclados
 * entre texto cifrado y claro.
 *
 * Uso:  ./test_race [milisegundos]   (por defecto 1500)
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>
#include <fcntl.h>
#include <unistd.h>
#include <time.h>
#include <sys/mman.h>

#define DEV   "/dev/mmapguard"
#define PGSZ  4096

static volatile int running = 1;
static char *g_map;
static long g_bad;    /* lecturas inconsistentes detectadas */
static long g_reads;  /* lecturas totales */

/* La página 0 descifrada debe comenzar con este prefijo conocido. */
static const char *EXPECTED = "[PAGINA_CONFIDENCIAL_0]";

static void *evictor(void *arg)
{
	(void)arg;
	while (running) {
		/* Forzar la expulsión de la página: el siguiente acceso re-falla. */
		madvise(g_map, PGSZ, MADV_DONTNEED);
	}
	return NULL;
}

static void *reader(void *arg)
{
	(void)arg;
	char buf[32];

	while (running) {
		memcpy(buf, (const void *)g_map, sizeof(buf) - 1);
		buf[sizeof(buf) - 1] = '\0';
		__sync_fetch_and_add(&g_reads, 1);
		/* Debe verse SIEMPRE el prefijo descifrado completo, nunca basura. */
		if (strncmp(buf, EXPECTED, strlen(EXPECTED)) != 0)
			__sync_fetch_and_add(&g_bad, 1);
	}
	return NULL;
}

int main(int argc, char **argv)
{
	long ms = (argc > 1) ? atol(argv[1]) : 1500;
	pthread_t th_e, th_r;
	int fd = open(DEV, O_RDWR);

	if (fd < 0) { perror("open " DEV); return 1; }

	g_map = mmap(NULL, PGSZ, PROT_READ, MAP_SHARED, fd, 0);
	if (g_map == MAP_FAILED) { perror("mmap"); return 1; }

	printf("[test_race] Lanzando evictor + reader durante %ld ms...\n", ms);
	pthread_create(&th_e, NULL, evictor, NULL);
	pthread_create(&th_r, NULL, reader, NULL);

	struct timespec ts = { ms / 1000, (ms % 1000) * 1000000L };
	nanosleep(&ts, NULL);
	running = 0;

	pthread_join(th_e, NULL);
	pthread_join(th_r, NULL);

	printf("[test_race] lecturas=%ld  inconsistentes=%ld\n", g_reads, g_bad);
	printf("[test_race] %s\n", g_bad == 0 ?
	       "OK: ninguna lectura corrupta bajo carrera (defensa consistente)." :
	       "ATENCION: se detectaron lecturas inconsistentes.");

	munmap(g_map, PGSZ);
	close(fd);
	return g_bad == 0 ? 0 : 1;
}
