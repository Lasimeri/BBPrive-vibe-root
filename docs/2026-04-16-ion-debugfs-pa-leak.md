# BB Priv — ION Debugfs Physical-Address Leak (2026-04-16)

**Target:** BlackBerry Priv STV100-2 · Android 6.0.1 · kernel 3.10.84-perf-ge617f3f · MSM8992 · Sept 2017 security patch · AAO474 · GRSecurity + CONFIG_DEBUG_LIST
**Attacker context:** adb shell, uid 2000 (`u:r:shell:s0`), no CAP_SYS_ADMIN / CAP_NET_RAW / user namespaces
**Status:** Confirmed on-device (read-only recon). Unblocks the 95% GPU root chain's primary gate.

---

## Summary

`/sys/kernel/debug/ion/heaps/<heap>` emits the **raw physical address** of every ION allocation, tagged by the allocating process's `comm`, in an ordinary `seq_file`.

Previous sessions concluded "all procfs pointer leaks are masked by GRSecurity." That is true for `%p` and `%pK`. It is **not** true for `%pa` — the physical-address specifier, used exclusively in the ION print paths, is never routed through `restricted_pointer()` and therefore bypasses `kptr_restrict` entirely.

Shell uid 2000 on this device has `r_file_perms` on `debugfs_ion` via the AOSP-derived sepolicy. The file is mode `rw-rw-r--` root:root and is readable without special capabilities. A client's allocation can be located in the dump by tagging the process via `prctl(PR_SET_NAME, ...)` before `ION_IOC_ALLOC`.

This directly resolves the "physical address of user-controlled ION page" blocker that closed out the Session 3 chain at 95% and that Session 4 deemed hardware-only.

---

## Observed on-device

```
$ adb shell cat /sys/kernel/debug/ion/heaps/audio
          client              pid             size
----------------------------------------------------
     mediaserver              631             4096
     mediaserver              631             4096
     ...
         voc_cal               50             4096
     voip_client               50             8192
----------------------------------------------------

Memory Map
          client  start address    end address           size
         voc_cal 0x0x00000000cb400000 0x0x00000000cb400fff           4096 (0x1000)
     voip_client 0x0x00000000cb401000 0x0x00000000cb401fff           4096 (0x1000)
     voip_client 0x0x00000000cb402000 0x0x00000000cb403fff           8192 (0x2000)
             631 0x0x00000000cb404000 0x0x00000000cb404fff           4096 (0x1000)
audio_cal_client 0x0x00000000cb404000 0x0x00000000cb404fff           4096 (0x1000)
             ...
```

Each row of the "Memory Map" section gives: client name, start PA, end PA, size. Correction to Session 3: the audio CMA heap's first-alloc PA is `0xCB400000`, not `0xCB800000`. Allocations inside the pool are sequential page-aligned.

The adsp heap (`/sys/kernel/debug/ion/heaps/adsp`) dumps the same format starting at PA `0xCD020000`. `qsecom` heap dumps clients but not the memory map (TrustZone-carveout heap with restricted print). `mm` and `system` heaps print client/pid/size only (system heap uses page-level SG; no contiguous PA to emit).

---

## Root cause

### The `%pa` format specifier

`lib/vsprintf.c:1159` implements `%pa` to emit `(unsigned long long)*((phys_addr_t *)ptr)` via the `number()` formatter with `SPECIAL|SMALL|ZEROPAD`. It does **not** flow through `restricted_pointer()` or consult `kptr_restrict`. That gate only exists for `%pK`.

### The ION print path

`drivers/staging/android/ion/ion.c:1720` `ion_heap_print_debug()` invokes the heap's `print_debug` op if set:

```c
heap->ops->print_debug(heap, s, &mem_map);
```

The CMA / carveout / removed implementations call:

```c
seq_printf(s, "%16.s 0x%14pa 0x%14pa %14lu (0x%lx)\n",
           client_name, &data->addr, &data->addr_end,
           data->size, data->size);
```

e.g. `drivers/staging/android/ion/ion_cma_heap.c:198`, `ion_carveout_heap.c:197`, `ion_removed_heap.c:274`, `ion_cma_secure_heap.c:806`.

`data->addr` and `data->addr_end` are raw `phys_addr_t` from the heap's own internal bookkeeping — not IOMMU IOVAs. `client_name` is `client->name`, which for userspace-owned ION clients is the task's `comm`. The prctl/comm-tag correlation lets the attacker find their own row.

### Sepolicy

Standard Android N `shell.te` grants `r_file_perms` on `debugfs_ion`, applied via the `genfscon debugfs /ion u:object_r:debugfs_ion:s0` rule inherited from AOSP. Verified by successfully reading from uid 2000 without SELinux denial.

---

## Exploit flow

```c
#include <sys/prctl.h>
#include <sys/ioctl.h>
#include <fcntl.h>

prctl(PR_SET_NAME, "LEAKME_<tag>");

int ion = open("/dev/ion", O_RDWR);
struct ion_allocation_data req = {
    .len          = 0x1000,
    .align        = 0x1000,
    .heap_id_mask = 1 << ION_AUDIO_HEAP_ID,   /* 28 → CMA audio */
    .flags        = ION_FLAG_CACHED,          /* 1 */
};
ioctl(ion, ION_IOC_ALLOC, &req);

/* cat /sys/kernel/debug/ion/heaps/audio in this or another shell,
 * grep for "LEAKME_<tag>" → extract start address. */
```

Subsequent allocations from the same heap are sequential, so a single leak anchors all future PAs in that pool.

---

## Why prior sessions missed it

Session 3/4 explicitly tested these channels and concluded they all failed:
- `/proc/self/pagemap` — `CAP_SYS_ADMIN`-gated
- `/proc/iomem`, `/proc/vmallocinfo`, `/proc/timer_list` — `%pK` masked
- `dmesg` — blocked
- `ION_IOC_PHYS` — not in kernel
- `ION_IOC_CUSTOM` — only cache ops
- KGSL ioctls — `memdesc+0x28` never copied to user
- GPU snapshot — offset 0x34 has TTBR0 only
- SMMU ATS → PAR — not captured in snapshot

The ION debugfs `%pa` dump was not in the audit set because "procfs-style kernel-pointer leak" was the mental model, and everyone assumed GRSecurity gates such dumps uniformly. It doesn't — `%pa` predates `kptr_restrict` and was never retrofitted behind it, because "a physical address is not a kernel pointer." For userspace ROP chains that need the PA of a user-controlled page, the distinction is invisible.

---

## What this does and doesn't unlock

**Unlocks:** any chain that needs the physical address of a user-owned page backed by a carveout/CMA/removed ION heap. Concretely, this is the missing step 3 of the Session 3 "95% chain":

```
STEP 3: ❌ → ✅  Get physical address of our ION page (for fake page table)
```

**Does not resolve:** Session 4's definitive conclusion that the GPU CP_MEM_WRITE primitive cannot reach SMMU context-bank registers (they are on the AHB/APB control bus, not the main data bus). The `TTBR0@0xF8008020` approach from Session 3 was microTLB caching, not actual register writes. So the identity-map-via-TTBR0-swap path is still closed even with the PA known.

**Opens up** (still to evaluate):
1. **CMA-migration-driven stale-TLB corruption.** CMA pages can be reclaimed for non-CMA use under memory pressure (`alloc_contig_range` → `migrate_pages`). With the PA known, the attacker can force a CMA allocation, keep a stale KGSL TLB entry alive, trigger CMA migration away from that PA, and have the GPU write into whatever kernel allocation lands there.
2. **Re-validation of the SMMU-write conclusion** against fresh KGSL buffers with the PA known in advance. Session 4 ruled the path dead based on "fresh buffers received the marker via the old PT"; with the PA known independently, the test can be tightened.
3. **DRAM-bank inference** for cache/timing side-channels.
4. **A clean CVE write-up** independent of whether it completes to root.

---

## Responsible-disclosure / CVP framing

- **Bug class:** CWE-200 information exposure via format specifier that bypasses `kptr_restrict`.
- **Severity on its own:** Low (InfoLeak). Physical address of attacker-owned memory, already partially exposed to userspace via mapping.
- **Severity in chain:** Enables otherwise-blocked GPU DMA attacks that need PA of a user buffer. Together with an SMMU-write primitive or stale-TLB primitive → local privilege escalation.
- **Affected:** Any Qualcomm MSM/APQ device with ION CMA/carveout heaps and a shell-readable `/sys/kernel/debug/ion/heaps/`. MSM8992 (Priv) confirmed. Likely all MSM8974/8994/8996/8998-era devices predating the upstream ION removal in Android 12.
- **Proposed fix:** Route `%pa` through `restricted_pointer()` when `kptr_restrict ≥ 1`, or unconditionally replace `%pa` with a masked variant in the ION debug path. Upstream ION was deprecated in favor of dma-buf heaps, so this primarily affects long-life devices on pre-Android-12 kernels.

---

## Verification

Verified on the device in the session that discovered this finding. PoC intentionally kept out of this repo.
