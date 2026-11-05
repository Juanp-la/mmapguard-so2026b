/* SPDX-License-Identifier: GPL-2.0 */
/**
 * @file mmapguard.h
 * @brief Definiciones internas compartidas del módulo MMAPGuard.
 * @course Sistemas Operativos - SO2026B (EAFIT)
 *
 * Reto: Seguridad de archivos en la capa del kernel sobre regiones mapeadas
 * con mmap(). Este encabezado agrupa las estructuras y prototipos que comparten
 * los tres módulos objeto del .ko (core, crypto y audit), de modo que cada
 * responsabilidad quede aislada y comprobable por separado.
 */
#ifndef _MMAPGUARD_H_
#define _MMAPGUARD_H_

#include <linux/types.h>
#include <linux/mm.h>
#include <linux/spinlock.h>
#include <linux/atomic.h>
#include "mmapguard_uapi.h"

/* Tamaño del "archivo" protegido respaldado por el driver: 8 páginas = 32 KiB. */
#define MG_NUM_PAGES    8
#define MG_STORE_BYTES  (MG_NUM_PAGES * PAGE_SIZE)

/* Nombre del dispositivo de caracteres y de la clase en /sys/class. */
#define MG_DEVICE_NAME  "mmapguard"
#define MG_CLASS_NAME   "mmapguard_class"

/* Entradas del registro de auditoría en memoria (ring buffer). */
#define MG_AUDIT_ENTRIES 128
#define MG_COMM_LEN      16

/**
 * enum mg_event - Tipos de evento auditables sobre la región protegida.
 * Se usan como índice legible en el registro y en los contadores globales.
 */
enum mg_event {
	MG_EV_OPEN = 0,     /* apertura del dispositivo                         */
	MG_EV_MMAP_OK,      /* mmap() aceptado tras validar política            */
	MG_EV_MMAP_DENY,    /* mmap() rechazado (uid no autorizado o W sobre RO)*/
	MG_EV_FAULT,        /* page fault servido con descifrado transparente   */
	MG_EV_MKWRITE_OK,   /* primera escritura autorizada sobre una página    */
	MG_EV_MKWRITE_DENY, /* intento de escritura sobre región de solo lectura*/
	MG_EV_SYNC,         /* msync()/writeback: recifrado + checksum          */
	MG_EV_INTEGRITY_BAD,/* checksum de integridad no coincide               */
	MG_EV_MAX
};

/**
 * struct mg_audit_rec - Un registro individual del ring de auditoría.
 * @seq:   número de secuencia monotónico del evento.
 * @ts_ns: marca de tiempo monotónica (ns) en que ocurrió.
 * @event: tipo de evento (enum mg_event).
 * @uid:   uid real del proceso que originó el evento.
 * @pid:   pid del proceso que originó el evento.
 * @pgoff: página (offset dentro del store) involucrada, o -1 si no aplica.
 * @comm:  nombre corto del ejecutable (current->comm).
 */
struct mg_audit_rec {
	u64 seq;
	u64 ts_ns;
	u32 event;
	u32 uid;
	s32 pid;
	s32 pgoff;
	char comm[MG_COMM_LEN];
};

/**
 * struct mg_state - Estado global del driver (una sola instancia).
 * @pages:        páginas físicas de respaldo (contenido descifrado en runtime).
 * @authorized_uid: uid autorizado a mapear y descifrar la región.
 * @readonly:     política de solo lectura (rechaza mapeos/escrituras W).
 * @plain_crc:    checksum CRC32 del texto plano de referencia (integridad).
 * @store_lock:   protege el acceso concurrente al almacén cifrado y a las páginas.
 * @counters:     contadores por tipo de evento (enum mg_event).
 */
struct mg_state {
	struct page *pages[MG_NUM_PAGES];
	u32  authorized_uid;
	bool readonly;
	u32  plain_crc;
	spinlock_t store_lock;
	atomic64_t counters[MG_EV_MAX];
};

extern struct mg_state mg;

/* ----- API del submódulo de criptografía (mg_crypto.c) -------------------- */

/**
 * mg_crypto_init_store() - Inicializa el almacén cifrado con un texto plano
 * pedagógico y calcula su CRC32 de referencia.
 */
void mg_crypto_init_store(void);

/**
 * mg_crypto_decrypt_to_page() - Descifra la página @idx del almacén y escribe
 * el texto plano en la página física @dst. Usada por el manejador .fault.
 * @idx: índice de página [0, MG_NUM_PAGES).
 * @dst: página física destino ya reservada.
 */
void mg_crypto_decrypt_to_page(unsigned long idx, struct page *dst);

/**
 * mg_crypto_encrypt_from_page() - Recifra el contenido de la página física
 * @src hacia el almacén en la posición @idx. Usada en msync()/writeback.
 */
void mg_crypto_encrypt_from_page(unsigned long idx, struct page *src);

/**
 * mg_crypto_verify_integrity() - Recalcula el CRC32 del texto plano actual y
 * lo compara contra el de referencia.
 * Return: true si la integridad se mantiene, false si fue alterada.
 */
bool mg_crypto_verify_integrity(u32 *computed_out);

/* ----- API del submódulo de auditoría (mg_audit.c) ------------------------ */

int  mg_audit_init(void);
void mg_audit_exit(void);

/**
 * mg_audit_log() - Registra un evento en el ring y actualiza el contador.
 * @event: tipo (enum mg_event); @pgoff: página o -1.
 */
void mg_audit_log(enum mg_event event, long pgoff);

/* Llena @out (capacidad @max) con las estadísticas actuales para el ioctl. */
void mg_audit_fill_stats(struct mg_stats *out);

#endif /* _MMAPGUARD_H_ */
