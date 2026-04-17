# BBPrive-vibe-root

Documentation log for software-only root research on the **BlackBerry Priv STV100-2** (Android 6.0.1, kernel 3.10.84-perf, MSM8992, Adreno 418, Sept 2017 security patch, AAO474 build, GRSecurity hardened).

The device is personally owned and research is conducted on it directly; no other people's devices are in scope. This repo is documentation, not a ready-to-run exploit kit.

## Status

95% of a GPU-DMA-based root chain has been built across prior sessions. The chain was blocked on a single gap — the physical address of a user-controlled ION page — which 14 prior attack vectors failed to leak and which Session 4 concluded was reachable only via hardware EDL.

**As of 2026-04-16 the PA-leak gap is closed** via a debugfs `%pa`-specifier bypass (see below). The chain's remaining open question is whether the PA leak plus existing primitives can reach a kernel-memory write, or whether the SMMU-inaccessible-from-GPU finding from Session 4 keeps the chain incomplete on its own.

## Target

| Field | Value |
|------|------|
| Model | BlackBerry Priv STV100-2 (Verizon) |
| Build | blackberry/venicevzwvzw/venice:6.0.1/MMB29M/AAO474 |
| Kernel | 3.10.84-perf-ge617f3f (2017-08-28) |
| SoC | Qualcomm Snapdragon 808 (MSM8992) |
| GPU | Adreno 418 |
| Security patch | 2017-09-05 |
| Mitigations | SELinux enforcing · GRSecurity (AUTOSLAB, %pK mask, pointer mask) · CONFIG_DEBUG_LIST · PXN · no KASLR |
| Attacker | uid 2000 (`u:r:shell:s0`), via USB ADB |

## Contents

- **`Initial Progress: Opus 4.6`** — Session 3/4 complete research log. 14 attack vectors explored, including the KGSL SMMU stale-TLB 0-day, CVE-2019-2215 iovec spray (dead on 3.10 + DEBUG_LIST), and the GPU IOMMU identity-map chain. Ends with "hardware EDL is the only path." Superseded by the 2026-04-16 PA-leak below.
- **`docs/2026-04-16-ion-debugfs-pa-leak.md`** — New finding: `/sys/kernel/debug/ion/heaps/<heap>` dumps raw `phys_addr_t` via `%pa`, which bypasses `kptr_restrict`. Shell-readable. Resolves the chain's primary blocker. Candidate for a standalone CVE.
- **`docs/2026-04-16-cve-2017-8890-port-plan.md`** — Porting plan for CVE-2017-8890 (IGMP double-free) from Nexus 6P to Priv. Port built and executed — mechanically correct, blocked at runtime by `sysctl_igmp_max_memberships` × GRSec AUTOSLAB.
- **`docs/2026-04-17-bb-secure-boot-chain-and-edl-path.md`** — Full analysis of the BB Priv secure-boot chain (PBL→SBL-1→aboot→bootsig→boot.img→dm-verity), the `authboot`/`pcauthtool`/`aveflash.lua` internal toolkit, cross-variant flash mechanics, why software root is exhausted on this firmware, and the EDL/firehose plan for the next session.

## Primitives confirmed on the device

1. **GPU CP_MEM_WRITE** to the KGSL global region (0xF8000000–0xF8009FFF) — writes land in memstore / scratch / ringbuffer data, not SMMU registers.
2. **GPU snapshot TTBR0 leak** — invalid TYPE3 opcode (0xFF) triggers a CP fault; snapshot at `/sys/class/kgsl/kgsl-3d0/snapshot/dump` offset 0x34 contains the current IOMMU page-table physical base. Changes per boot.
3. **KGSL SMMU stale-TLB write-after-free (0-day)** — `IOCTL_KGSL_SHAREDMEM_FREE` updates the SMMU page tables without flushing the GPU's internal microTLB. Reliable at ~85% when the target page is pinned (e.g. via `vmsplice`). CWE-416 via CWE-672.
4. **ION CMA allocation with known physical layout** — audio heap (id 28) allocates sequentially from base 0xCB400000; adsp heap (id 22) from 0xCD020000. Per-alloc PA now directly leakable.
5. **ION_IOC_INV_CACHES** — flushes CPU caches for arbitrary userspace VMA pages; can be used to synchronize GPU DMA writes with CPU reads despite the lack of hardware coherency between GPU and CPU for these ION buffers.

## Closed-off paths (from prior sessions)

CVE-2019-2215 iovec spray · CVE-2019-2215 BPF spray · CVE-2016-8655 (af_packet) · CVE-2017-1000112 (UDP UFO) · CVE-2016-2067 (GPU VDSO) · CVE-2016-5195 (DirtyCOW) · KGSL perfcounter overflow (EDB-39504) · ADSPRPC races · GPU CP_SET_PROTECTED_MODE on A4xx · All quadrooter CVEs · All standard procfs pointer-leak surfaces (all `%pK`/kptr_restrict masked).

The new PA-leak does **not** resurrect any of these — it is a new primitive, not a patch bypass.

## Caveat

The SMMU register bank (physical 0xFDB10000+) sits on the MSM AHB/APB control bus and is **not** reachable from GPU DMA. Session 4 empirically confirmed this with fresh KGSL buffers that bypass the GPU microTLB cache. The PA-leak finding does not change that: the chain still needs an independent kernel-memory write primitive, or a new way to reach SMMU registers, before it reaches code execution.

## License and use

Research documentation. Not a root tool. Do not run against devices you do not own.
