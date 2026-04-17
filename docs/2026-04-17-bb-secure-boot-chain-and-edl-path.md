# BB Priv Secure-Boot Chain Analysis and EDL Path (2026-04-17)

Research from one evening's attempt to flash a modified `boot.img` onto a BlackBerry Priv STV100-2 via every non-EDL software path, documenting what each layer actually enforces and why all non-hardware paths are closed on the current firmware.

## Device under test

| | |
|---|---|
| Model | BlackBerry Priv (codename `venice`) |
| Hardware | STV100-2 (Verizon SKU) — hardware identity confirmed |
| Firmware | AAO474 (Aug 2017, Sept 2017 security patch) — variant:vzw subvariant:vzw hlos-sig-tag:vzw |
| Bootloader | `kernel:lk` · `authboot_api_ver:1.3` · `security:enabled` · `hlos_unsigned.tkn:disabled` · `hlos_signature.tkn:NONE` |
| Serial | `1163530142` |

## USB modes observed during the session

| VID:PID | Mode | How to reach | What speaks it |
|---|---|---|---|
| `0fca:803a` | Android running / ADB | normal boot | `adb` |
| `0fca:8030` | BB bootloader menu — actually BB's fastboot | power off, Vol-Down + Power | `fastboot` (partial) + `authboot` |
| `05c6:9008` | Qualcomm EDL | *not reached this session* | `edl.py` + firehose `.mbn` |

Important: the device's on-screen "Reboot into Fastboot" option is a stub on Verizon-locked units — selecting it triggers a normal cold boot. The useful interface is the bootloader-menu USB mode (`0fca:8030`), which **is** Qualcomm fastboot under the hood.

## The BB Priv secure-boot chain (what actually blocks root)

Layered from silicon up:

1. **PBL (Primary Bootloader)** in Qualcomm ROM — verifies SBL-1 signature. Cannot be replaced.
2. **SBL-1** (`sbl1_signed.mbn`) — verifies aboot. Signed by Qualcomm-rooted chain.
3. **aboot** (`emmc_appsboot.mbn`) — verifies boot.img + recovery.img + the `bootsig`/`recoverysig` delegate cert partitions. Implements the `authboot` protocol extensions over Qualcomm's standard fastboot. Labbala (XDA 2015) reverse-engineered aboot and confirmed no exploitable bugs — this study stood up over the session's re-verification.
4. **boot.img** — kernel + ramdisk. Verified by aboot against `bootsig` at flash time and again on cold boot.
5. **kernel** — GRSecurity-hardened 3.10.84-perf, CONFIG_DEBUG_LIST enabled, no KASLR. Kernel-level attack surface exhausted in prior sessions (see `Initial Progress: Opus 4.6`).
6. **dm-verity** over `system` — final gate; prevents any post-boot partition tamper.

The signed `boot.img.sig` / `recovery.img.sig` files are **delegate certificates**, not image hashes. Evidence: in AAO474 both files are byte-identical 208-byte blobs. The per-image hash verification lives inside the mbn-style boot.img container itself, verified against the delegate cert's authority. This means you cannot modify `boot.img` and re-use the stock `bootsig`; the internal signature breaks.

Signature blob layout (ECC-512 / `ec_agent`):

```
+0x00  0EF50B41   cookie (low byte is device-family discriminator:
                    0x41='A' = venice/qc8992, 0x53='S' = bbb100/qc8953)
+0x04  "ec_agent"  8-byte agent identifier
+0x10  "YYYYMMDD.HHMMSS"  build/sign timestamp (ASCII)
+0x20  "APBI"|"ADBI"|"ABBI"|"MFI"  token type
+0x24  sigtag (32 bytes, e.g. "vzw" left-padded with nulls)
+0x44  0x80 bytes signature + padding
```

Token types: **APBI** = Authorized Production Boot Image, **ADBI** = Authorized Debug Boot Image, **ABBI** = base, **MFI** = manufacturing.

Our device's aboot will accept an image whose delegate cert has:
- matching device cookie (`0x0EF50B41` for venice), AND
- matching token type that the device is configured to trust (currently **only APBI**), AND
- matching sigtag against `hlos-sig-tag` (currently **vzw**).

Loosening any of these requires installing a BB-signed *debug token* (`hlos_unsigned.tkn` or equivalent) into NV — a partition-level write of a blob that is itself verified by aboot's embedded BB public key. The token provisioning service (`stmtokenservice.rim.net/stmserver/desktop/tokens`, hard-coded in `authboot`) has been offline since BlackBerry exited mobile; no public leak of pre-signed tokens exists.

## `authboot` + `pcauthtool` + `aveflash.lua` — the BB internal build toolkit

Extracted from a leaked `AAO.zip` BB-internal build artifact. Confirms the architecture above:

- **`authboot`** (ELF, Linux/macOS/Windows) speaks an extended fastboot with:
  - Standard flashing commands (`flash`, `erase`, `format`, `getvar`, `boot`, `reboot`).
  - `flashing unlock` / `unlock_critical` — the official unlock path.
  - `flash debug_token <filename>` — **takes a signed debug token** and writes to NV.
  - `debugtokens` (RTAS-protected) — downloads whitelisted tokens from the BB token server and uploads them. Requires valid RIMNET credentials → dead.
  - `getvarp` for RTAS-protected variables (`bsn`, `pin`, `procid`, `authbootlog`).
  - `-q <url>` overrides the token server URL. `-x <file.zip>` saves fetched tokens locally.
- **`pcauthtool`** — interactive RTAS authentication. `-b` bypasses the check for commands that don't need it, but `debugtokens` does need it. The RIMNET domain is gone; `pcauthtool` cannot authenticate.
- **`aveflash.lua`** — the top-level Lua orchestrator that `flashall.sh` invokes. Handles per-variant signature file selection via `match_sig_tag(token, sigtag, hlossigtag)` and per-variant oem image selection via device_properties files.

Confirmed: `flashall.sh`'s carrier gate is a shell-level string compare of `getvar hlos-sig-tag` against the script's target (`vzw` for AAO474, empty for AAW068, variant+subvariant=`na` for AAC826). **Running the individual `fastboot flash` commands manually bypasses this gate.** The bootloader itself accepts any BB-signed image whose delegate cert matches the device's trust configuration.

## Fastboot `oem` command surface

Enumerated from labbala's 2015 reverse-engineering of aboot plus our live probing:

```
flashing unlock          requires BB-signed unlock token
flashing unlock_critical requires signed token for bootloader partitions
oem mmcinfo              read-only
oem info                 read-only — returns build version (AAO474 confirmed)
oem bootlog              read-only
oem bootmetrics          read-only
oem dmesg                read-only
oem gptinfo              read-only — dumps partition table
oem mmchealth            read-only
oem enable-charger-screen / disable-charger-screen
oem enable-usb-reset / enable-usb-shutdown
oem led:<state>
oem set-factory-mode     hard-disabled on production firmware
oem set-product-mode
oem securewipe           full-device erase (destructive)
oem blocklist-wipe
oem grswipe
oem format <partition>
oem erase-ddr-training-primary / -backup
oem getvarp:<name>       RTAS-protected
oem clear-anti-theft     requires RTAS
oem clear-lal
oem console              debug console entry
```

Most `oem` commands silently hang from our setup until the device is reinitialized — the state gets fragile after a few failed queries. `oem info` reliably works right after fresh fastboot entry.

## Cross-variant flashing — how AT&T hardware can end up running VZW firmware

The research and flashall analysis both confirm: carrier-variant enforcement is entirely in the `flashall.sh` shell wrapper (it reads `hlos-sig-tag` via `getvar` and string-compares). The bootloader accepts any BB-signed delegate cert for its hardware family. The community-documented technique (XDA thread 3447949):

1. Unzip the target autoloader (e.g. AT&T STV100-3).
2. Optionally replace `oem.img` with one from another variant (carrier-specific apps/settings; sig-tag isn't in here).
3. Delete or comment the shell's `getvar hlos-sig-tag` gate.
4. Run the `fastboot flash tz/hyp/sdi/pmic/rpm/sbl1/aboot/bootsig/recoverysig/boot/recovery/...` sequence.
5. Device comes up reporting the new variant because `hlos-sig-tag` is *read from the newly-flashed `bootsig` partition*.

Net effect: the device's self-reported variant follows whichever `bootsig` was last written. This is identity flipping, not a signing bypass — you're still flashing BB-signed images, just for a different carrier.

## Why none of this yields root

Even with cross-variant flash wide open, every flashable `boot.img` is BB-signed. The only way to boot a *modified* kernel is:

- **Have the BB ECC-512 signing key.** Not public, not leaked.
- **Install a BB-signed `hlos_unsigned.tkn` debug token.** Requires RTAS auth + live BB token server → impossible post-BB-exit.
- **Exploit aboot.** Labbala audited aboot in 2015, found it clean; nothing has changed on AAO474.
- **Exploit TrustZone or SBL-1.** Deep QSEE work, far out of scope for a single-device project and gated on MSM8992 TZ vulns that haven't been public.

The only remaining mechanical path is physical-level: EDL mode direct partition writes. This bypasses fastboot's signature enforcement at the write protocol, but does **not** bypass aboot's boot-time verification — so EDL alone doesn't give root either. It would let us dump `persist` / `bbpersist` / `devcfg` for analysis and potentially modify non-secure-boot state, but the boot chain stays intact.

## The EDL cable reality

Standard "button cable" deep-flash cables trigger EDL on many Qualcomm devices by shorting specific USB pins at power-on. On the Priv STV100-2 the button cable we tried triggered the BB **bootloader menu** (PID `0fca:8030`) instead of EDL (PID `05c6:9008`). This suggests either:
- The cable's short configuration doesn't match what the Priv's SBL-1 expects for EDL trigger, or
- The Priv's SBL-1 intercepts the short and routes it to the BB menu rather than 9008.

Community references indicate Priv EDL entry typically requires either:
- A cable specifically wired for MSM8992 (150 kΩ between USB ID and GND is the commonly documented spec), or
- Physical test-point shorting on the PCB (requires disassembly).

`adb reboot edl` is closed on AAO474 — CVE-2017-13174 patched. This was verified by testing; `adb reboot edl` causes a normal reboot.

## Resources on-host, ready for the EDL session

| Path | What it is |
|---|---|
| `~/Downloads/AAO/` | BB internal build kit (`authboot`, `pcauthtool`, Lua orchestrator). Not for the Priv target_ (it's KeyOne-scoped at `target/product/bbry_qc8953/`), but the host binaries are platform-agnostic. |
| `~/Downloads/bbry_qc8992_autoloader_user-vzw-vzw-AAO474/` | Stock AAO474 (current device firmware) |
| `~/Downloads/BlackBerry_Priv_STV100-2_QC8992_AAW068_270318_CMD/` | AAW068 (Mar 2018, global/empty sig-tag) |
| `~/Downloads/Blackberry Priv_qc8992_Autoloader_user-na-none-AAC826/` | AAC826 (launch, Nov 2015, pre-patches) |
| `/home/lasi/blackberry-priv/firehose-programmers/MSM8992.mbn` | MSM8992 firehose loader (already on host) |
| `/home/lasi/blackberry-priv/firehose-programmers/MSM8992_OneLabsTools.mbn` | Leaked auth-bypass variant |
| `/home/lasi/blackberry-priv/edl-tools/edl.py` | bkerler's edl tool |

Upstream `bkerler/edl` moves fast; worth `git pull` (or re-clone) right before the EDL session.

## Plan for the next session (when EDL entry is possible)

1. Enter EDL via known-good cable or motherboard test points.
2. `./edl printgpt --loader=MSM8992.mbn` — inspect partition layout.
3. Dump non-destructive, signature-bearing partitions for analysis:
   - `persist`, `bbpersist`, `devcfg`, `pmic` (for completeness).
   - `sbl1` (read-only; for secure-boot chain study).
4. Grep the dumps for `hlos`, `vzw`, `att`, `tkn`, `sigtag` strings.
5. If the sigtag is stored in a non-fuse-bound region (`bbpersist` is the likely candidate based on partition naming), modify and write back. Verify behavior change via `fastboot getvar hlos-sig-tag`.
6. If sigtag is fuse-bound or dm-verity-protected, stop — the signing-key problem is the terminal wall for all unsigned-kernel paths.
7. Final fallback: Chimera Tool (or equivalent commercial box) — the only bundled package that consistently lists a working BB Priv module in 2026. ~$30/mo subscription. Research flagged it as the one paid path still current.

## Closed-off paths for the record (so future-me doesn't redo them)

- `adb reboot edl` — patched.
- Button-cable direct EDL on this specific cable — triggers BB menu, not 9008.
- Kernel-level root via CVE-2019-2215 — `CONFIG_DEBUG_LIST` BUGs on list_del corruption.
- Kernel-level root via CVE-2017-8890 — compiles + runs on device but sysctl_igmp_max_memberships × GRSec AUTOSLAB leaves the double-free spray density-starved.
- GPU TTBR0 identity-map swap — SMMU context-bank registers not GPU-DMA-reachable on MSM8992 (verified with a valid LPAE PT at a leaked PA).
- CVE-2017-13174 — patched.
- CVE-2017-11176 (mq_notify) — `CONFIG_POSIX_MQUEUE=n`.
- BB-specific services fuzzing — callable but require deodexing we don't have.
- `com.blackberry.tokenloader` dial code — routes to dead OTA endpoint.
- RTAS authentication via `pcauthtool` — requires live RIMNET; server offline.

## Open questions worth checking before committing to hardware work

- Does `persist` or `bbpersist` actually contain the `hlos-sig-tag` string, or is it sourced from a fuse / OTP register at boot? Answered by EDL dump + grep.
- Does the BB bootloader consult a writeable `devcfg` partition for its allow-list of acceptable delegate-cert authorities? Answered by EDL dump + RE.
- Does Chimera Tool's Priv module actually work on AAO474 in 2026? Answered by purchase + attempt (last-resort paid validation).

## References

- Deep research on cross-carrier Priv flashing — Exa research ID `r_01kpdws45gz5hyfhcacb7q3917`, output cached in session transcript.
- XDA 3447949 — cross-carrier autoloader swap.
- XDA root bounty 3243716 — labbala's 2015 aboot analysis.
- `bkerler/edl`, `bkerler/Loaders` — the current best public EDL tooling; issue #130 is the canonical "anyone have a patched MSM8992 firehose?" thread.
- `zenlty/Qualcomm-Firehose` — public MSM8992.mbn mirror.
- This repo: `docs/2026-04-16-ion-debugfs-pa-leak.md` (the session's CVP-worthy find), `docs/2026-04-16-cve-2017-8890-port-plan.md`.
