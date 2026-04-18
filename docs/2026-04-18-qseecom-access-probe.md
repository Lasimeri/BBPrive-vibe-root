# `/dev/qseecom` accessibility probe — results (2026-04-18)

Post-recovery empirical test of CVE-2021-1961's access gate on AAO474. Device is stock-restored AAO474 after the flash-attempts session. ADB is up, shell uid 2000 at SELinux context `u:r:shell:s0`.

## Observed

```
$ adb shell 'ls -laZ /dev/qseecom'
/dev/qseecom: Permission denied

$ adb shell 'dmesg | grep qseecom | tail -3'
avc: denied { getattr } for pid=28006 comm="ls" path="/dev/qseecom"
  scontext=u:r:shell:s0 tcontext=u:object_r:tee_device:s0 tclass=chr_file permissive=0
```

## Analysis

`/dev/qseecom` is typed `u:object_r:tee_device:s0`. Shell domain (`u:r:shell:s0`) has **zero** access to `tee_device:chr_file` — not even `getattr`. The SELinux policy on AAO474 strictly gates Qualcomm TEE device access to specific privileged domains: `qseecomd`, `mediaserver`, `drmserver`, `keystore`, `gatekeeperd`. Shell is not among them.

The CVE-2021-1961 PoC author (Tamir Zahavi-Brunner) demonstrates the exploit running as `su - system` with context `u:r:magisk:s0` — meaning Magisk was the vehicle for domain transition. On a stock device with SELinux enforcing, pure shell-uid access to `/dev/qseecom` is not a path forward.

## Components that ARE present and reachable

| Component | Path | Shell access |
|---|---|---|
| Widevine TA binary | `/system/etc/firmware/widevine.mdt` + `.b00`–`.b03` | read-accessible (genfs) |
| QSEEComAPI client library | `/system/vendor/lib{,64}/libQSEEComAPI.so` | read-accessible |
| Widevine Java framework | `/system/framework/com.google.widevine.software.drm.jar` | read-accessible |
| `drm.drmManager` binder service | `service list` shows it | **reachable via `service call`** (returns parcels) |
| `media.player`, `media.audio_flinger`, `android.security.keystore` | binder | **reachable via `service call`** |
| `qseecomd` userspace daemon | init.svc.qseecomd=running | reachable indirectly via drm/media services |
| `bbauthtoold` | `/system/bin/bbauthtoold` (owner root:shell mode 755, `system_file:s0`) | **executable from shell** (warning: hangs if run without args — avoid) |

Blocked from shell (SELinux denial on exec or read):
- `/system/bin/qseecom_sample_client` (`sectest_exec:s0`)
- `/system/bin/qseecom_security_test` (`sectest_exec:s0`)
- `/system/bin/oemwvtest` (`sectest_exec:s0`)
- `/system/bin/bb_tokenserviced`, `bbauthd` (their own `*_exec:s0` types)
- `/system/bin/mediaserver`, `drmserver`, `keystore` (not exec by shell)

## The exploit path this implies

```
Our APK (installed via adb install, runs as untrusted_app)
  │
  ├─ Uses MediaDrm API (android.media.MediaDrm)
  │
  │  Binder → drm.drmManager (drmserver)
  │           │
  │           Uses libQSEEComAPI.so → /dev/qseecom ioctl
  │                                    │
  │                                    Widevine TA  ← CVE-2021-1961 overflow target
```

Every link is present. The exploit has to come from an **APK**, not from the ADB shell. `untrusted_app` → `drm.drmManager` binder transition is explicitly allowed by stock AOSP Android 6.0 sepolicy (required for apps to consume DRM video).

## What the APK needs to do

Per Tamir Zahavi-Brunner's blog + PoC (`github.com/tamirzb/CVE-2021-1961`):

1. Create a `MediaDrm` object with the Widevine UUID: `{ 0xedef8ba9, 0x79d6, 0x4ace, { 0xa3, 0xc8, 0x27, 0xdc, 0xd5, 0x1d, 0x21, 0xed } }`.
2. Use one of these request paths to reach the vulnerable Widevine TA commands:
   - `openSession()` → `getProvisionRequest()`
   - `getKeyRequest()` with crafted initData
3. Craft the payload so that when it reaches the Widevine TA, it triggers the buffer-overflow in `__qseecom_update_cmd_buf_64` — specifically, the path where a command buffer length check is missed and the TA writes past the intended buffer into attacker-specified physical addresses.
4. The primitive is **arbitrary physical memory write** (from TrustZone context → any RAM address), which bypasses ASLR, CFI, GRSec AUTOSLAB, DEBUG_LIST (all of which operate on kernel virtual addresses).
5. Locate `selinux_enforcing` (from our `vmlinux.elf` at `0xffffffc001648238` — Priv has no KASLR so this is fixed), overwrite with `0x00`.
6. Locate `current->cred`, overwrite uid with 0. Or use `commit_creds(prepare_kernel_cred(0))` by scheduling a kernel function pointer to fire.
7. Side-channel result back to the ADB shell via a write to `/data/local/tmp/rooted` or equivalent.

## Alternative paths (if MediaDrm API can't cleanly carry the overflow)

1. **Port Tamir's C PoC to JNI inside the APK**. Bundle `libQSEEComAPI.so` (which is already on device — just `System.load()` it). The JNI lib, running in the app's process at `untrusted_app:s0`, will itself fail to open `/dev/qseecom` — **so this variant doesn't work directly**.
2. **Mediaserver code exec via an Android 6 CVE**. Any unpatched-on-Sept-2017 mediaserver bug (some Stagefright variants, heap corruptions in audio/video codecs). Land code exec at `mediaserver:s0`, then run the CVE-2021-1961 primitive natively. Harder to find, potentially more direct.
3. **Find any other domain with qseecom access that shell can transition to**. `gatekeeperd`, `keystore`, `drmserver` — probe their input surfaces. Most are binder-only, which brings us back to the MediaDrm-like problem.

## Immediate next steps

1. Set up an Android development environment on the host (Android Studio or standalone SDK + NDK).
2. Build a minimal test APK that calls `MediaDrm.getProvisionRequest()` with well-formed input, install via `adb install`, confirm it reaches the Widevine TA (check `dmesg` for qseecom interaction logs).
3. Once the path is confirmed reachable, port Tamir's overflow-trigger payload into the APK.
4. Run, observe kernel panic / root shell / nothing.

## Complete session artifacts on host

- `/home/lasi/blackberry-priv/cve-2021-1961/` — Tamir's PoC cloned, NDK Android.mk included.
- `/home/lasi/blackberry-priv/cve-2021-1961/test-qseecom-access.sh` — the probe script used tonight.
- `/home/lasi/blackberry-priv/dirtycow/` — CVE-2016-5195 PoC (not applicable on AAO474, kept for reference).
- `~/Downloads/bbry_qc8992_autoloader_user-vzw-vzw-AAO474/` — known-good recovery image (used twice this session).
- This repo: https://github.com/Lasimeri/BBPrive-vibe-root
