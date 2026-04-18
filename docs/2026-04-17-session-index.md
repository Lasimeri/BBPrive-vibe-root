# Session index — 2026-04-17 (into 2026-04-18)

Navigational index for the two-day research arc. Read top-to-bottom for the chronological thread; each item links to its full writeup.

## Day 1 (2026-04-16)

1. **PA leak discovery** — `/sys/kernel/debug/ion/heaps/<heap>` emits `phys_addr_t` via `%pa` specifier bypassing `kptr_restrict`. Resolves the long-standing "PA of a user ION page" gap that had closed out the GPU chain at 95%.
   → `docs/2026-04-16-ion-debugfs-pa-leak.md`

2. **Re-verified Session-4 SMMU-inaccessibility** — with a valid LPAE identity-map PT at a leaked real PA and 64-bit TTBR0 writes, 0/5 candidate offsets swap TTBR0. SMMU context-bank registers confirmed not reachable from GPU CP_MEM_WRITE. The strongest rebuttal to the TTBR0-swap path.
   → `docs/2026-04-16-ion-debugfs-pa-leak.md` (the negative finding section)

3. **CVE-2017-8890 port** — Nexus 6P PoC ported to Priv AAO474 (all symbols wired, valid LPAE PT, kernel_setsockopt addr_limit-flip primitive). Runs through all stages without panic. Blocked at spray density by `sysctl_igmp_max_memberships` (cap ~500) × GRSec AUTOSLAB.
   → `docs/2026-04-16-cve-2017-8890-port-plan.md`

4. **BB secure-boot chain analysis** — full understanding of PBL → SBL-1 → aboot → bootsig → boot.img → dm-verity. Documented the `authboot`/`pcauthtool`/`aveflash.lua` toolkit from a leaked BB internal build artifact (AAO.zip). Mapped the .sig delegate-cert structure (cookie, APBI/ADBI tokens, sigtag).
   → `docs/2026-04-17-bb-secure-boot-chain-and-edl-path.md`

## Day 2 (2026-04-17 → 2026-04-18)

5. **AAF153 downgrade attempt** — pre-DirtyCOW June 2016 build. All `fastboot flash` commands returned OKAY, but cold-boot dropped straight into fastboot. First sign that aboot silently discards unauthorized writes.

6. **`erase bootsig` discovery** — `fastboot erase bootsig` before `flash bootsig` DOES let a new delegate cert commit (verified via `oem info`'s `HLOS boot Signature Information` fields showing the flashed cert's Time/ID/Tag). But `hlos-sig-tag` does NOT change — confirming the sigtag is fuse-bound.

7. **AAW068 Rest-of-Planet attempt** — same erase-first trick, same failure. Cert commits but boot.img silently rejected on cold-boot fuse-vs-cert mismatch.

8. **Two research agents converge on CVE-2021-1961** — Exa deep-research-pro + in-session Sonnet agent independently identify Tamir Zahavi-Brunner's Qualcomm QSEE/qseecom buffer overflow (Sept 2021 patch, AAO474 is 4 years behind) as the remaining viable attack surface. TrustZone-based arbitrary physical memory R/W. Bypasses GRSec, ASLR, CFI, DEBUG_LIST because it writes physical RAM directly. PoC: https://github.com/tamirzb/CVE-2021-1961

   → `docs/2026-04-17-flash-attempts-and-cve-2021-1961.md`

9. **Device recovered twice** via `oem securewipe` + full `flashall.sh`. Confirmed reliable restore procedure.

## What's queued for the next session

- **Verify `/dev/qseecom` reachability from shell uid 2000 on AAO474** — test script at `/home/lasi/blackberry-priv/cve-2021-1961/test-qseecom-access.sh`. Non-destructive probe of SELinux context, permissions, and TA presence.
- If reachable: port PoC to aarch64-linux-gnu toolchain (since we don't have Android NDK), adapt kallsyms offsets from our `vmlinux.elf` (no KASLR on Priv — all symbols are at fixed addresses), run, observe.
- If not directly reachable from shell: investigate lesser userspace privescs to uid 1000 on AAO474 to chain into qseecom access.

## Resources staged on host

- Cloned: `/home/lasi/blackberry-priv/cve-2021-1961/` (Tamir's PoC repo)
- Test script: `/home/lasi/blackberry-priv/cve-2021-1961/test-qseecom-access.sh`
- Built: `/home/lasi/blackberry-priv/dirtycow/dcow_aarch64` (DirtyCOW PoC, not used because downgrade failed)
- Built: `/home/lasi/blackberry-priv/dirtycow/simple_runas_payload` (minimal 952 B setresuid+execve payload)
- Downloaded: `~/Downloads/bbry_qc8992_autoloader_user-common-AAF153.zip` (pre-DirtyCOW firmware, kept for future attempts if EDL opens up)
- Extracted: AAO474, AAW068 ROP, AAW068 T-Mobile, AAC826 launch — all Priv autoloaders
- Toolkit: `~/Downloads/AAO/` — BB internal `authboot`, `pcauthtool`, `aveflash.lua`
- Repo: https://github.com/Lasimeri/BBPrive-vibe-root

## The persistent conclusion

Two complete research arcs on this device have now landed on hardware-level attack paths (eMMC desolder + prototype aboot; EDL test-point short; TrustZone primitive). The signing regime, anti-rollback, fuse-bound sigtag, and dead RTAS infrastructure close every software-only path through the bootloader. CVE-2021-1961 is the **one** remaining path that avoids all of that — it's a pure runtime kernel attack that bypasses the boot chain entirely. That's where next session picks up.
