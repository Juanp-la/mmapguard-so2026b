// SPDX-License-Identifier: GPL-2.0
/**
 * @file mg_audit.c
 * @brief Auditoría de accesos: ring buffer en memoria + contadores + /proc.
 * @course Sistemas Operativos - SO2026B (EAFIT)
 *
 * ROL DENTRO DEL RETO
 * -------------------
 * Toda operación relevante sobre la región mapeada (mmap aceptado/denegado,
 * page fault, primera escritura, sincronización, fallo de integridad) se
 * registra con uid, pid, comm y marca de tiempo monotónica. El registro se
 * expone de forma legible en /proc/mmapguard, que es el punto de inspección
 * forense del defensor. Los contadores agregados se entregan por ioctl.
 */
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/proc_fs.h>
#include <linux/seq_file.h>
#include <linux/sched.h>
#include <linux/cred.h>
#include <linux/ktime.h>
#include <linux/spinlock.h>
#include <linux/string.h>
#include "mmapguard.h"

static struct mg_audit_rec mg_ring[MG_AUDIT_ENTRIES];
static u64 mg_ring_head;          /* total de eventos registrados (monotónico) */
static DEFINE_SPINLOCK(mg_ring_lock);
static struct proc_dir_entry *mg_proc_entry;

static const char *mg_event_name(u32 ev)
{
	switch (ev) {
	case MG_EV_OPEN:          return "OPEN";
	case MG_EV_MMAP_OK:       return "MMAP_OK";
	case MG_EV_MMAP_DENY:     return "MMAP_DENY";
	case MG_EV_FAULT:         return "FAULT";
	case MG_EV_MKWRITE_OK:    return "MKWRITE_OK";
	case MG_EV_MKWRITE_DENY:  return "MKWRITE_DENY";
	case MG_EV_SYNC:          return "SYNC";
	case MG_EV_INTEGRITY_BAD: return "INTEGRITY_BAD";
	default:                  return "?";
	}
}

void mg_audit_log(enum mg_event event, long pgoff)
{
	struct mg_audit_rec *rec;
	unsigned long flags;

	if (event >= MG_EV_MAX)
		return;

	atomic64_inc(&mg.counters[event]);

	spin_lock_irqsave(&mg_ring_lock, flags);
	rec = &mg_ring[mg_ring_head % MG_AUDIT_ENTRIES];
	rec->seq   = mg_ring_head++;
	rec->ts_ns = ktime_get_ns();
	rec->event = event;
	rec->uid   = from_kuid(&init_user_ns, current_uid());
	rec->pid   = current->pid;
	rec->pgoff = (s32)pgoff;
	strscpy(rec->comm, current->comm, MG_COMM_LEN);
	spin_unlock_irqrestore(&mg_ring_lock, flags);
}

void mg_audit_fill_stats(struct mg_stats *out)
{
	int i;

	memset(out, 0, sizeof(*out));
	for (i = 0; i < MG_EV_MAX && i < MG_STATS_SLOTS; i++)
		out->counters[i] = atomic64_read(&mg.counters[i]);

	out->authorized_uid = mg.authorized_uid;
	out->readonly = mg.readonly ? 1 : 0;
	out->plain_crc = mg.plain_crc;
	out->integrity_ok = mg_crypto_verify_integrity(&out->live_crc) ? 1 : 0;
}

/* ----- /proc/mmapguard: volcado legible del registro de auditoría -------- */

static int mg_proc_show(struct seq_file *m, void *v)
{
	unsigned long flags;
	u64 total, start, i;
	int ev;

	seq_puts(m, "== MMAPGuard :: estado y auditoria ==\n");
	seq_printf(m, "uid_autorizado = %u\n", mg.authorized_uid);
	seq_printf(m, "solo_lectura   = %s\n", mg.readonly ? "si" : "no");
	seq_printf(m, "crc_referencia = 0x%08x\n", mg.plain_crc);

	seq_puts(m, "\n-- contadores por evento --\n");
	for (ev = 0; ev < MG_EV_MAX; ev++)
		seq_printf(m, "  %-14s : %lld\n", mg_event_name(ev),
			   (long long)atomic64_read(&mg.counters[ev]));

	seq_puts(m, "\n-- ultimos eventos (seq | t[ms] | evento | uid | pid | comm | pag) --\n");

	spin_lock_irqsave(&mg_ring_lock, flags);
	total = mg_ring_head;
	start = total > MG_AUDIT_ENTRIES ? total - MG_AUDIT_ENTRIES : 0;
	for (i = start; i < total; i++) {
		struct mg_audit_rec *r = &mg_ring[i % MG_AUDIT_ENTRIES];

		seq_printf(m, "  %6llu | %9llu | %-13s | %5u | %6d | %-12s | %d\n",
			   r->seq, div_u64(r->ts_ns, 1000000ULL),
			   mg_event_name(r->event), r->uid, r->pid,
			   r->comm, r->pgoff);
	}
	spin_unlock_irqrestore(&mg_ring_lock, flags);

	return 0;
}

static int mg_proc_open(struct inode *inode, struct file *file)
{
	return single_open(file, mg_proc_show, NULL);
}

static const struct proc_ops mg_proc_ops = {
	.proc_open    = mg_proc_open,
	.proc_read    = seq_read,
	.proc_lseek   = seq_lseek,
	.proc_release = single_release,
};

int mg_audit_init(void)
{
	mg_ring_head = 0;
	memset(mg_ring, 0, sizeof(mg_ring));

	mg_proc_entry = proc_create(MG_DEVICE_NAME, 0444, NULL, &mg_proc_ops);
	if (!mg_proc_entry) {
		pr_err("[mmapguard] No se pudo crear /proc/%s\n", MG_DEVICE_NAME);
		return -ENOMEM;
	}

	pr_info("[mmapguard] Auditoria lista en /proc/%s\n", MG_DEVICE_NAME);
	return 0;
}

void mg_audit_exit(void)
{
	if (mg_proc_entry)
		proc_remove(mg_proc_entry);
}
