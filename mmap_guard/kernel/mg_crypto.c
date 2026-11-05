// SPDX-License-Identifier: GPL-2.0
/**
 * @file mg_crypto.c
 * @brief Cifrado transparente y verificación de integridad del almacén.
 * @course Sistemas Operativos - SO2026B (EAFIT)
 *
 * ROL DENTRO DEL RETO
 * -------------------
 * Responde a la pregunta de "cifrado transparente en memoria": el contenido
 * confidencial vive CIFRADO en el almacén de respaldo del driver (simulando el
 * estado en disco). Solo cuando un proceso AUTORIZADO provoca un page fault, el
 * manejador .fault invoca mg_crypto_decrypt_to_page() para materializar el texto
 * plano en una página física recién reservada. Al sincronizar (msync) se vuelve
 * a cifrar con mg_crypto_encrypt_from_page(). Así, el texto descifrado nunca se
 * persiste y queda acotado a la página del proceso autorizado.
 *
 * NOTA ACADÉMICA HONESTA: se usa un keystream XOR derivado de una clave + offset
 * de página con fines DIDÁCTICOS (observar el efecto del cifrado en un volcado de
 * memoria). NO es criptografía de grado productivo; en una solución real se
 * usaría la Crypto API del kernel (AES-GCM vía crypto_aead). La limitación se
 * documenta explícitamente en el informe (sección de trabajo futuro).
 */
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/mm.h>
#include <linux/highmem.h>
#include <linux/crc32.h>
#include <linux/string.h>
#include "mmapguard.h"

/* Clave base del keystream didáctico (parámetro del módulo en mg_core.c). */
extern u32 mg_xor_key;

/*
 * Almacén "en disco": copia cifrada persistente del contenido. Se mantiene
 * separada de las páginas físicas que ve el usuario para poder demostrar que
 * en el respaldo el contenido está ilegible.
 */
static u8 mg_store_enc[MG_STORE_BYTES];

/*
 * Texto plano de referencia. Se conserva únicamente para calcular el CRC32 de
 * integridad; no se expone jamás al espacio de usuario.
 */
static u8 mg_plain_ref[MG_STORE_BYTES];

/**
 * mg_keystream_byte() - Byte de keystream para una posición absoluta.
 * @pos: offset absoluto dentro del almacén.
 *
 * Mezcla la clave, la posición y el índice de página para que páginas distintas
 * no compartan el mismo keystream (evita el patrón trivial de XOR constante).
 */
static inline u8 mg_keystream_byte(unsigned long pos)
{
	u32 page = pos / PAGE_SIZE;
	u32 k = mg_xor_key + (page * 0x9E3779B1u) + (u32)pos;

	k ^= k >> 13;
	k *= 0x85EBCA6Bu;
	k ^= k >> 16;
	return (u8)(k & 0xFF);
}

void mg_crypto_init_store(void)
{
	unsigned long i, off = 0;

	/* Construir un texto plano pedagógico distinto por página. */
	for (i = 0; i < MG_NUM_PAGES; i++) {
		char tmp[512];
		int n;

		n = snprintf(tmp, sizeof(tmp),
			"[PAGINA_CONFIDENCIAL_%lu] Contenido protegido por MMAPGuard.\n"
			"Solo visible en claro para el uid autorizado tras un page fault.\n"
			"En el almacen de respaldo estos bytes estan cifrados.\n",
			i);

		/*
		 * snprintf devuelve la longitud que TENDRIA el texto completo,
		 * que puede exceder el tamano del buffer; acotar antes del memcpy
		 * evita leer fuera de 'tmp' (corrupcion de pila del kernel).
		 */
		if (n < 0)
			n = 0;
		if (n >= (int)sizeof(tmp))
			n = sizeof(tmp) - 1;

		memset(mg_plain_ref + i * PAGE_SIZE, 0, PAGE_SIZE);
		memcpy(mg_plain_ref + i * PAGE_SIZE, tmp, n);
	}

	/* Cifrar el texto plano hacia el almacén de respaldo. */
	spin_lock(&mg.store_lock);
	for (off = 0; off < MG_STORE_BYTES; off++)
		mg_store_enc[off] = mg_plain_ref[off] ^ mg_keystream_byte(off);

	mg.plain_crc = crc32(0, mg_plain_ref, MG_STORE_BYTES);
	spin_unlock(&mg.store_lock);

	pr_info("[mmapguard] Almacen cifrado inicializado (%d paginas, CRC ref=0x%08x)\n",
		MG_NUM_PAGES, mg.plain_crc);
}

void mg_crypto_decrypt_to_page(unsigned long idx, struct page *dst)
{
	unsigned long base = idx * PAGE_SIZE;
	u8 *kaddr;
	unsigned long i;

	if (idx >= MG_NUM_PAGES || !dst)
		return;

	kaddr = kmap_local_page(dst);
	spin_lock(&mg.store_lock);
	for (i = 0; i < PAGE_SIZE; i++)
		kaddr[i] = mg_store_enc[base + i] ^ mg_keystream_byte(base + i);
	spin_unlock(&mg.store_lock);
	kunmap_local(kaddr);
}

void mg_crypto_encrypt_from_page(unsigned long idx, struct page *src)
{
	unsigned long base = idx * PAGE_SIZE;
	u8 *kaddr;
	unsigned long i;

	if (idx >= MG_NUM_PAGES || !src)
		return;

	kaddr = kmap_local_page(src);
	spin_lock(&mg.store_lock);
	for (i = 0; i < PAGE_SIZE; i++) {
		u8 plain = kaddr[i];

		/*
		 * Reflejar el cambio en el texto plano actual y recifrar el
		 * almacen. NOTA: NO se recalcula mg.plain_crc aqui a proposito;
		 * el CRC de referencia se fija una sola vez al inicializar y
		 * actua como huella inmutable (modelo tripwire). Asi, toda
		 * divergencia respecto al contenido base queda en evidencia al
		 * verificar la integridad.
		 */
		mg_plain_ref[base + i] = plain;
		mg_store_enc[base + i] = plain ^ mg_keystream_byte(base + i);
	}
	spin_unlock(&mg.store_lock);
	kunmap_local(kaddr);
}

bool mg_crypto_verify_integrity(u32 *computed_out)
{
	u32 live;

	spin_lock(&mg.store_lock);
	live = crc32(0, mg_plain_ref, MG_STORE_BYTES);
	spin_unlock(&mg.store_lock);

	if (computed_out)
		*computed_out = live;

	return live == mg.plain_crc;
}
