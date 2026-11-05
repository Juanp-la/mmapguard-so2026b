/* SPDX-License-Identifier: GPL-2.0 */
/**
 * @file mmapguard_uapi.h
 * @brief Contrato (UAPI) compartido entre el módulo de kernel y el espacio de
 *        usuario: comandos ioctl y estructuras de intercambio.
 *
 * Al usar <linux/types.h> (__u32/__s32/__u64) el mismo encabezado compila tanto
 * dentro del kernel como en los programas de prueba de usuario.
 */
#ifndef _MMAPGUARD_UAPI_H_
#define _MMAPGUARD_UAPI_H_

#include <linux/types.h>
#include <linux/ioctl.h>

#define MG_IOC_MAGIC 'G'

/* Debe coincidir con MG_EV_MAX del encabezado interno. */
#define MG_STATS_SLOTS 8

/**
 * struct mg_stats - Instantánea de contadores de auditoría expuesta a usuario.
 * @counters: un contador por tipo de evento (ver enum mg_event del kernel).
 * @authorized_uid: uid actualmente autorizado.
 * @readonly: 1 si la región está en modo de solo lectura.
 * @integrity_ok: 1 si el último chequeo de integridad fue correcto.
 * @plain_crc: CRC32 de referencia del texto plano.
 * @live_crc: CRC32 recalculado en el momento de la consulta.
 */
struct mg_stats {
	__u64 counters[MG_STATS_SLOTS];
	__u32 authorized_uid;
	__u32 readonly;
	__u32 integrity_ok;
	__u32 plain_crc;
	__u32 live_crc;
	__u32 _pad;
};

/* Consultar estadísticas y estado de integridad. */
#define MG_IOC_GET_STATS   _IOR(MG_IOC_MAGIC, 1, struct mg_stats)
/* Forzar una verificación de integridad (recalcula CRC y audita si falla). */
#define MG_IOC_CHECK       _IO(MG_IOC_MAGIC, 2)
/* Cambiar el uid autorizado (solo root/CAP_SYS_ADMIN). */
#define MG_IOC_SET_UID     _IOW(MG_IOC_MAGIC, 3, __u32)
/* Activar/desactivar el modo de solo lectura (solo root/CAP_SYS_ADMIN). */
#define MG_IOC_SET_RO      _IOW(MG_IOC_MAGIC, 4, __u32)

#endif /* _MMAPGUARD_UAPI_H_ */
