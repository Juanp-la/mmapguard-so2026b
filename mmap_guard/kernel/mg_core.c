// SPDX-License-Identifier: GPL-2.0
/**
 * @file mg_core.c
 * @brief Núcleo de MMAPGuard: dispositivo de caracteres, política de mmap y
 *        operaciones de memoria virtual (demand paging con control de acceso).
 * @course Sistemas Operativos - SO2026B (EAFIT)
 *
 * ARQUITECTURA DE LA DEFENSA (por qué en el kernel)
 * -------------------------------------------------
 * El punto de intercepción es el callback .mmap del driver de caracteres y las
 * vm_operations_struct del VMA resultante. A diferencia de un envoltorio en
 * espacio de usuario (LD_PRELOAD), que un atacante elude trivialmente, aquí el
 * control vive en Ring 0 sobre la estructura vm_area_struct creada por el
 * kernel, por lo que TODO acceso a la región mapeada pasa por nuestra lógica:
 *
 *   mmap()        -> dev_mmap():    valida uid y política (RO/RW) antes de
 *                                   aceptar el VMA; endurece vm_flags.
 *   1er acceso    -> mg_vma_fault(): valida uid del proceso que falla y sirve la
 *                                   página descifrada por demanda (#PF).
 *   1a escritura  -> mg_vma_mkwrite(): audita y bloquea escrituras sobre región
 *                                   de solo lectura.
 *   msync/unmap   -> mg_vma_close()/ioctl: recifra el contenido y conserva la
 *                                   huella de integridad.
 */
#include <linux/init.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/fs.h>
#include <linux/cdev.h>
#include <linux/device.h>
#include <linux/mm.h>
#include <linux/slab.h>
#include <linux/uaccess.h>
#include <linux/cred.h>
#include <linux/capability.h>
#include <linux/sched.h>
#include "mmapguard.h"

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Juan Pablo Lopera Arrazola - SO2026B EAFIT");
MODULE_DESCRIPTION("MMAPGuard: control de acceso, cifrado transparente y auditoria de regiones mmap en la capa de kernel");
MODULE_VERSION("1.0");

/* ----- Parámetros de módulo (configurables en insmod) --------------------- */
static uint authorized_uid = 0;
module_param(authorized_uid, uint, 0644);
MODULE_PARM_DESC(authorized_uid, "uid autorizado a mapear/descifrar la region (def: 0)");

static bool readonly;
module_param(readonly, bool, 0644);
MODULE_PARM_DESC(readonly, "si es true, rechaza mapeos/escrituras con PROT_WRITE");

u32 mg_xor_key = 0xA5A5A5A5u;
module_param_named(xor_key, mg_xor_key, uint, 0644);
MODULE_PARM_DESC(xor_key, "clave base del keystream didactico de cifrado");

/* ----- Estado global ------------------------------------------------------ */
struct mg_state mg;

static int major_number;
static struct class *mg_class;
static struct device *mg_device;
static struct cdev mg_cdev;

/* Marca qué páginas ya fueron materializadas (descifradas) en RAM. */
static bool mg_page_live[MG_NUM_PAGES];

/* Comprueba si el llamante actual está autorizado (uid exacto o CAP_SYS_ADMIN). */
static bool mg_caller_authorized(void)
{
	u32 uid = from_kuid(&init_user_ns, current_uid());

	return (uid == mg.authorized_uid) || capable(CAP_SYS_ADMIN);
}

/* ======================= vm_operations_struct ============================= */

/**
 * mg_vma_fault - Sirve una página por demanda con descifrado y control de uid.
 *
 * Se invoca desde handle_mm_fault() cuando la MMU detecta una PTE vacía. Aquí
 * aplicamos una segunda barrera: aunque el VMA ya fue autorizado en mmap(), el
 * proceso que realmente provoca el fallo (p. ej., un hijo tras fork) se vuelve a
 * validar. Esto materializa el aislamiento de visibilidad entre procesos.
 */
static vm_fault_t mg_vma_fault(struct vm_fault *vmf)
{
	unsigned long idx = vmf->pgoff;
	struct page *page;

	if (idx >= MG_NUM_PAGES) {
		mg_audit_log(MG_EV_MMAP_DENY, idx);
		return VM_FAULT_SIGBUS;
	}

	if (!mg_caller_authorized()) {
		pr_warn("[mmapguard] FAULT denegado: uid=%u pid=%d intento leer pagina %lu\n",
			from_kuid(&init_user_ns, current_uid()), current->pid, idx);
		mg_audit_log(MG_EV_MMAP_DENY, idx);
		return VM_FAULT_SIGBUS;
	}

	page = mg.pages[idx];
	if (!page)
		return VM_FAULT_SIGBUS;

	/* Materializar (descifrar) la página solo la primera vez. */
	spin_lock(&mg.store_lock);
	if (!mg_page_live[idx]) {
		spin_unlock(&mg.store_lock);
		mg_crypto_decrypt_to_page(idx, page);
		spin_lock(&mg.store_lock);
		mg_page_live[idx] = true;
	}
	spin_unlock(&mg.store_lock);

	get_page(page);
	vmf->page = page;

	mg_audit_log(MG_EV_FAULT, idx);
	pr_info("[mmapguard] FAULT servido: uid=%u pid=%d pagina=%lu PFN=0x%lx\n",
		from_kuid(&init_user_ns, current_uid()), current->pid,
		idx, page_to_pfn(page));
	return 0;
}

/*
 * NOTA DE DISEÑO (importante):
 * No se instala un manejador .page_mkwrite. El contrato de page_mkwrite exige
 * que la página involucrada pertenezca a un address_space (page->mapping != NULL,
 * como las páginas de la Page Cache). Nuestras páginas provienen de alloc_page()
 * y NO tienen mapping; si se devolviera 0 desde page_mkwrite, el kernel la toma
 * por "truncada" y reintenta el fallo indefinidamente (livelock). Por eso la
 * política de ESCRITURA se refuerza en dev_mmap(): en modo solo lectura se
 * rechaza PROT_WRITE y se limpian VM_WRITE/VM_MAYWRITE, de modo que ninguna
 * escritura puede siquiera generar un fallo sobre la región. El recifrado del
 * contenido modificado se realiza al cerrar el VMA (mg_vma_close).
 */

/* Al cerrar el VMA recifra las páginas vivas y preserva el respaldo cifrado. */
static void mg_vma_close(struct vm_area_struct *vma)
{
	unsigned long i;

	for (i = 0; i < MG_NUM_PAGES; i++) {
		bool live;

		spin_lock(&mg.store_lock);
		live = mg_page_live[i];
		spin_unlock(&mg.store_lock);

		if (live) {
			mg_crypto_encrypt_from_page(i, mg.pages[i]);
			mg_audit_log(MG_EV_SYNC, i);
		}
	}
	pr_info("[mmapguard] VMA cerrado: contenido recifrado en el almacen.\n");
}

static const struct vm_operations_struct mg_vm_ops = {
	.fault = mg_vma_fault,
	.close = mg_vma_close,
};

/* ============================ file_operations ============================= */

static int dev_open(struct inode *inodep, struct file *filep)
{
	mg_audit_log(MG_EV_OPEN, -1);
	return 0;
}

static int dev_release(struct inode *inodep, struct file *filep)
{
	return 0;
}

/**
 * dev_mmap - Punto de intercepción principal: autoriza o rechaza el VMA.
 */
static int dev_mmap(struct file *filp, struct vm_area_struct *vma)
{
	unsigned long size = vma->vm_end - vma->vm_start;
	bool wants_write = (vma->vm_flags & VM_WRITE);

	/* Barrera 1: control de acceso por identidad. */
	if (!mg_caller_authorized()) {
		pr_warn("[mmapguard] mmap DENEGADO: uid=%u pid=%d no autorizado (uid_ok=%u)\n",
			from_kuid(&init_user_ns, current_uid()), current->pid,
			mg.authorized_uid);
		mg_audit_log(MG_EV_MMAP_DENY, -1);
		return -EACCES;
	}

	/* Barrera 2: límite de tamaño de la región. */
	if (size > MG_STORE_BYTES) {
		pr_err("[mmapguard] mmap DENEGADO: tamano %lu > limite %lu\n",
		       size, (unsigned long)MG_STORE_BYTES);
		mg_audit_log(MG_EV_MMAP_DENY, -1);
		return -EINVAL;
	}

	/* Barrera 3: política de solo lectura. */
	if (mg.readonly && wants_write) {
		pr_warn("[mmapguard] mmap DENEGADO: PROT_WRITE sobre region de solo lectura (uid=%u pid=%d)\n",
			from_kuid(&init_user_ns, current_uid()), current->pid);
		mg_audit_log(MG_EV_MMAP_DENY, -1);
		return -EACCES;
	}

	/*
	 * Endurecimiento contra la evasion O_RDONLY + mprotect(PROT_WRITE):
	 * en modo solo lectura retiramos VM_MAYWRITE y VM_WRITE del VMA, de modo
	 * que un mprotect() posterior a escritura falle con -EACCES. Sin esto, un
	 * proceso podria crear una copia COW privada escribible del contenido.
	 */
	if (mg.readonly)
		vm_flags_clear(vma, VM_WRITE | VM_MAYWRITE);

	vma->vm_ops = &mg_vm_ops;

	mg_audit_log(MG_EV_MMAP_OK, -1);
	pr_info("[mmapguard] mmap ACEPTADO: uid=%u pid=%d size=%lu write=%d ro=%d\n",
		from_kuid(&init_user_ns, current_uid()), current->pid,
		size, wants_write, mg.readonly);
	return 0;
}

static long dev_ioctl(struct file *filp, unsigned int cmd, unsigned long arg)
{
	void __user *uarg = (void __user *)arg;

	switch (cmd) {
	case MG_IOC_GET_STATS: {
		struct mg_stats st;

		mg_audit_fill_stats(&st);
		if (copy_to_user(uarg, &st, sizeof(st)))
			return -EFAULT;
		return 0;
	}
	case MG_IOC_CHECK: {
		u32 live;
		bool ok = mg_crypto_verify_integrity(&live);

		if (!ok) {
			mg_audit_log(MG_EV_INTEGRITY_BAD, -1);
			pr_warn("[mmapguard] INTEGRIDAD ALTERADA: crc_vivo=0x%08x != ref=0x%08x\n",
				live, mg.plain_crc);
			return -EILSEQ;
		}
		pr_info("[mmapguard] Integridad OK (crc=0x%08x)\n", live);
		return 0;
	}
	case MG_IOC_SET_UID: {
		u32 nuid;

		if (!capable(CAP_SYS_ADMIN))
			return -EPERM;
		if (copy_from_user(&nuid, uarg, sizeof(nuid)))
			return -EFAULT;
		mg.authorized_uid = nuid;
		pr_info("[mmapguard] uid autorizado cambiado a %u\n", nuid);
		return 0;
	}
	case MG_IOC_SET_RO: {
		u32 ro;

		if (!capable(CAP_SYS_ADMIN))
			return -EPERM;
		if (copy_from_user(&ro, uarg, sizeof(ro)))
			return -EFAULT;
		mg.readonly = ro ? true : false;
		pr_info("[mmapguard] modo solo_lectura = %d\n", mg.readonly);
		return 0;
	}
	default:
		return -ENOTTY;
	}
}

static const struct file_operations mg_fops = {
	.owner          = THIS_MODULE,
	.open           = dev_open,
	.release        = dev_release,
	.mmap           = dev_mmap,
	.unlocked_ioctl = dev_ioctl,
	.compat_ioctl   = dev_ioctl,
};

/* ============================ init / exit ================================= */

static int __init mmapguard_init(void)
{
	dev_t dev_num;
	int ret, i;

	pr_info("[mmapguard] Cargando MMAPGuard (uid_autorizado=%u, solo_lectura=%d)\n",
		authorized_uid, readonly);

	/* Inicializar estado. */
	memset(&mg, 0, sizeof(mg));
	spin_lock_init(&mg.store_lock);
	mg.authorized_uid = authorized_uid;
	mg.readonly = readonly;
	for (i = 0; i < MG_EV_MAX; i++)
		atomic64_set(&mg.counters[i], 0);

	/* Reservar las páginas físicas de respaldo. */
	for (i = 0; i < MG_NUM_PAGES; i++) {
		mg.pages[i] = alloc_page(GFP_KERNEL | __GFP_ZERO);
		if (!mg.pages[i]) {
			ret = -ENOMEM;
			goto err_free_pages;
		}
		mg_page_live[i] = false;
	}

	/* Inicializar el almacén cifrado y la huella de integridad. */
	mg_crypto_init_store();

	/* Inicializar la auditoría (/proc). */
	ret = mg_audit_init();
	if (ret)
		goto err_free_pages;

	/* Registrar el dispositivo de caracteres. */
	ret = alloc_chrdev_region(&dev_num, 0, 1, MG_DEVICE_NAME);
	if (ret < 0)
		goto err_audit;
	major_number = MAJOR(dev_num);

	cdev_init(&mg_cdev, &mg_fops);
	mg_cdev.owner = THIS_MODULE;
	ret = cdev_add(&mg_cdev, dev_num, 1);
	if (ret < 0)
		goto err_unregister;

	mg_class = class_create(MG_CLASS_NAME);
	if (IS_ERR(mg_class)) {
		ret = PTR_ERR(mg_class);
		goto err_cdev;
	}

	mg_device = device_create(mg_class, NULL, dev_num, NULL, MG_DEVICE_NAME);
	if (IS_ERR(mg_device)) {
		ret = PTR_ERR(mg_device);
		goto err_class;
	}

	pr_info("[mmapguard] Listo: /dev/%s (major=%d), /proc/%s\n",
		MG_DEVICE_NAME, major_number, MG_DEVICE_NAME);
	return 0;

err_class:
	class_destroy(mg_class);
err_cdev:
	cdev_del(&mg_cdev);
err_unregister:
	unregister_chrdev_region(dev_num, 1);
err_audit:
	mg_audit_exit();
err_free_pages:
	for (i = 0; i < MG_NUM_PAGES; i++)
		if (mg.pages[i])
			__free_page(mg.pages[i]);
	return ret;
}

static void __exit mmapguard_exit(void)
{
	dev_t dev_num = MKDEV(major_number, 0);
	int i;

	device_destroy(mg_class, dev_num);
	class_destroy(mg_class);
	cdev_del(&mg_cdev);
	unregister_chrdev_region(dev_num, 1);
	mg_audit_exit();

	for (i = 0; i < MG_NUM_PAGES; i++)
		if (mg.pages[i])
			__free_page(mg.pages[i]);

	pr_info("[mmapguard] Modulo descargado y recursos liberados.\n");
}

module_init(mmapguard_init);
module_exit(mmapguard_exit);
