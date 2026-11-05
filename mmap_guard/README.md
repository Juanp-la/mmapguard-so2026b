# MMAPGuard — Seguridad de archivos en la capa del kernel sobre `mmap()`

> **Curso:** Sistemas Operativos — SO2026B (EAFIT)
> **Reto:** Diseñar e implementar una solución en la **capa de kernel** que
> refuerce seguridad, integridad y control de acceso sobre archivos mapeados con
> `mmap()`: aislamiento de memoria, prevención de modificaciones no autorizadas y
> auditoría de accesos.
> **Referencia base:** [SO2026B/USOS/CapaKernel](https://github.com/evalenciEAFIT/SO2026B/tree/main/USOS/CapaKernel)

---

## 1. ¿Qué hace?

`MMAPGuard` es un **módulo de kernel (LKM)** que expone un dispositivo de
caracteres `/dev/mmapguard` respaldado por un "archivo confidencial" de 8 páginas
(32 KiB). Sobre las regiones que un proceso mapea con `mmap()`, el módulo aplica,
**desde Ring 0**, cuatro defensas que un envoltorio en espacio de usuario
(`LD_PRELOAD`) no podría garantizar:

| Defensa | Dónde se intercepta | Resultado |
|---|---|---|
| **Control de acceso por identidad** | `.mmap` + `.fault` | Solo el `uid` autorizado (o `CAP_SYS_ADMIN`) puede mapear y descifrar. |
| **Política de solo lectura + anti-evasión** | `.mmap` (`vm_flags_clear`) | Rechaza `PROT_WRITE` y neutraliza la escalada vía `mprotect()`. |
| **Cifrado transparente por demanda** | `.fault` / `.close` | El contenido vive cifrado en el respaldo; se descifra página a página solo para el proceso autorizado tras un *page fault*. |
| **Auditoría + integridad** | todos los hooks + `/proc/mmapguard` | Registro forense (uid/pid/comm/tiempo) y huella CRC32 tipo *tripwire*. |

---

## 2. Estructura del proyecto

```
mmap_guard/
├── kernel/                     # Módulo de kernel (se compila en mmapguard.ko)
│   ├── mmapguard.h             # Estructuras y prototipos internos
│   ├── mmapguard_uapi.h        # Contrato ioctl kernel<->usuario (UAPI)
│   ├── mg_core.c               # chardev + .mmap + vm_ops (política y demand paging)
│   ├── mg_crypto.c             # Cifrado transparente + integridad CRC32
│   ├── mg_audit.c              # Ring buffer de auditoría + /proc/mmapguard
│   └── Makefile                # Build del .ko (clean build, -Wall)
├── tests/                      # Clientes de prueba en espacio de usuario
│   ├── test_access.c           # Camino autorizado: leer/escribir/stats/integridad
│   ├── test_readonly.c         # Política RO + mitigación mprotect
│   ├── test_race.c             # Concurrencia madvise(DONTNEED)+lecturas
│   ├── bench.c                 # Sobrecosto: ruta protegida vs. anónima
│   └── Makefile
├── scripts/
│   ├── run_demo.sh             # Demostración guiada de los 5 escenarios
│   └── measure_overhead.sh     # strace / perf / ftrace
├── INFORME.md                  # Informe (Partes I, II y III) + rúbrica
└── README.md                   # Este archivo
```

---

## 3. Compilación

Requiere los *headers* del kernel en ejecución (`linux-headers-$(uname -r)`),
`gcc` y `make`. Compatible con **Linux 5.x / 6.x**.

```bash
# 1) Módulo de kernel
make -C kernel                 # genera kernel/mmapguard.ko

# 2) Clientes de prueba
make -C tests                  # genera test_access, test_readonly, test_race, bench
```

> **Verificado:** compila **sin advertencias** (*clean build*) contra
> `linux-headers-6.8.0-147-generic`. La única nota es ambiental (*the compiler
> differs from the one used to build the kernel*), no proviene del código.

---

## 4. Carga y ejecución (requiere root)

```bash
# Cargar con el uid actual autorizado y lectura/escritura
sudo insmod kernel/mmapguard.ko authorized_uid=$(id -u) readonly=0
sudo chmod 666 /dev/mmapguard

# Probar el camino autorizado
./tests/test_access

# Ver la auditoría en vivo
cat /proc/mmapguard

# Recargar en modo solo lectura y probar la política
sudo rmmod mmapguard
sudo insmod kernel/mmapguard.ko authorized_uid=$(id -u) readonly=1
sudo chmod 666 /dev/mmapguard
./tests/test_readonly

# Descargar
sudo rmmod mmapguard
```

**Demostración completa (5 escenarios + auditoría + benchmark):**

```bash
sudo ./scripts/run_demo.sh
```

**Parámetros del módulo** (`insmod mmapguard.ko <param>=<valor>`):

| Parámetro | Def. | Descripción |
|---|---|---|
| `authorized_uid` | `0` | uid autorizado a mapear/descifrar. |
| `readonly` | `0` | `1` rechaza mapeos/escrituras `PROT_WRITE`. |
| `xor_key` | `0xA5A5A5A5` | Clave base del keystream didáctico. |

---

## 5. Prueba en VM (recomendado para no arriesgar el equipo anfitrión)

Cargar módulos propios puede causar un *kernel panic* si hay un error. Se
recomienda probar en una VM desechable:

```bash
# Opción A: en tu Kali/Ubuntu dentro de VirtualBox/VMware (ya tiene headers).
sudo apt-get install -y linux-headers-$(uname -r) build-essential
make -C kernel && sudo ./scripts/run_demo.sh

# Opción B: QEMU con una imagen cloud de Ubuntu (ver INFORME.md, Parte III).
```

---

## 6. Interfaz `ioctl`

| Comando | Efecto |
|---|---|
| `MG_IOC_GET_STATS` | Devuelve contadores, estado e integridad (`struct mg_stats`). |
| `MG_IOC_CHECK` | Recalcula el CRC32 y reporta `-EILSEQ` si difiere del baseline. |
| `MG_IOC_SET_UID` | Cambia el uid autorizado (requiere `CAP_SYS_ADMIN`). |
| `MG_IOC_SET_RO` | Activa/desactiva solo lectura (requiere `CAP_SYS_ADMIN`). |

---

## 7. Limitaciones conocidas (honestidad técnica)

- El cifrado es un **keystream XOR didáctico**, no criptografía de grado
  productivo. En una versión real se usaría la **Crypto API** del kernel
  (`crypto_aead`, AES-GCM). Ver *Trabajo futuro* en el informe.
- El recifrado al respaldo se realiza en `.close` del VMA (munmap), no en cada
  `msync()` de páginas con *backing* de `address_space`.
- No sustituye a un LSM completo; es una prueba de concepto de los puntos de
  intercepción. Ver la matriz de compensaciones en el informe.

---

## 8. Integrantes

- Juan Pablo Lopera Arrazola — GitHub [`Juanp-la`](https://github.com/Juanp-la)
- Samuel Rendón Pabón
- Juan Diego Albánez López
- Daniel Esteban Muñetón Navarro

Ingeniería de Sistemas, EAFIT. Curso SO2026B.

**Repositorio:** https://github.com/Juanp-la/mmapguard-so2026b
