// SPDX-License-Identifier: GPL-2.0
/**
 * @file bench.c
 * @brief Medición del sobrecosto de la ruta mmap protegida vs. un mmap anónimo
 *        de referencia, usando getrusage() (fallos de página menores) y
 *        clock_gettime() (latencia de establecimiento + primer toque).
 * @course Sistemas Operativos - SO2026B (EAFIT)
 *
 * Mide, por iteración: mmap() + tocar cada página (forzando los page faults que
 * atiende nuestro .fault con descifrado + auditoría) + munmap(). Compara contra
 * el mismo patrón sobre memoria anónima (sin kernel hook) para aislar el
 * sobrecosto introducido por la defensa.
 *
 * Uso:  ./bench [iteraciones]   (por defecto 2000)
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>
#include <time.h>
#include <sys/mman.h>
#include <sys/resource.h>

#define DEV   "/dev/mmapguard"
#define PGSZ  4096
#define NPAGE 8
#define BYTES (PGSZ * NPAGE)

static double now_ns(void)
{
	struct timespec ts;

	clock_gettime(CLOCK_MONOTONIC, &ts);
	return ts.tv_sec * 1e9 + ts.tv_nsec;
}

/* Recorre una región tocando un byte por página (volatile evita que el
 * compilador elimine la lectura). */
static unsigned long touch(volatile char *p)
{
	unsigned long acc = 0;
	int i;

	for (i = 0; i < NPAGE; i++)
		acc += p[i * PGSZ];
	return acc;
}

int main(int argc, char **argv)
{
	long iters = (argc > 1) ? atol(argv[1]) : 2000;
	struct rusage r0, r1;
	double t0, t1, t_dev, t_anon;
	long i;
	volatile unsigned long sink = 0;

	int fd = open(DEV, O_RDWR);
	if (fd < 0) {
		perror("open " DEV);
		return 1;
	}

	/* --- Ruta PROTEGIDA (/dev/mmapguard) --- */
	getrusage(RUSAGE_SELF, &r0);
	t0 = now_ns();
	for (i = 0; i < iters; i++) {
		char *m = mmap(NULL, BYTES, PROT_READ, MAP_SHARED, fd, 0);
		if (m == MAP_FAILED) { perror("mmap dev"); return 1; }
		sink += touch(m);
		munmap(m, BYTES);
	}
	t1 = now_ns();
	getrusage(RUSAGE_SELF, &r1);
	t_dev = (t1 - t0) / iters;
	long minflt_dev = r1.ru_minflt - r0.ru_minflt;

	/* --- Ruta de REFERENCIA (anónima, sin hook) --- */
	getrusage(RUSAGE_SELF, &r0);
	t0 = now_ns();
	for (i = 0; i < iters; i++) {
		char *m = mmap(NULL, BYTES, PROT_READ | PROT_WRITE,
			       MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
		if (m == MAP_FAILED) { perror("mmap anon"); return 1; }
		sink += touch(m);
		munmap(m, BYTES);
	}
	t1 = now_ns();
	getrusage(RUSAGE_SELF, &r1);
	t_anon = (t1 - t0) / iters;
	long minflt_anon = r1.ru_minflt - r0.ru_minflt;

	printf("=============================================================\n");
	printf(" Benchmark MMAPGuard  (%ld iteraciones, %d paginas/iter)\n", iters, NPAGE);
	printf("=============================================================\n");
	printf(" Ruta PROTEGIDA  : %8.1f ns/iter | minflt total=%ld\n", t_dev, minflt_dev);
	printf(" Ruta ANONIMA    : %8.1f ns/iter | minflt total=%ld\n", t_anon, minflt_anon);
	printf(" Sobrecosto abs. : %8.1f ns/iter\n", t_dev - t_anon);
	if (t_anon > 0)
		printf(" Sobrecosto rel. : %8.1f %%\n", 100.0 * (t_dev - t_anon) / t_anon);
	printf("-------------------------------------------------------------\n");
	printf(" (sink=%lu, ignorar)\n", sink);

	close(fd);
	return 0;
}
