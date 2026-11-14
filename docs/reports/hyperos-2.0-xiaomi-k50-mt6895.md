# Report: HyperOS 2.0 (Xiaomi Redmi K50, MT6895) — SU Manager list always empty, and the standalone core panics at trigger

> Submitted on behalf of a device owner. Full logcat captures available on request.
> Nothing here was run against any other device; the phone is a personal device and every panic below was recoverable (page cache only, reboot restores it, userdata untouched).

## Device / build

| | |
|---|---|
| Device | Xiaomi Redmi K50 (`rubens`, `22041211AC`), MediaTek MT6895 (Dimensity 8100) |
| ROM | HyperOS `OS2.0.10.0.ULNCNMXM`, Android 14 (SDK 34), `ro.build.type=user` |
| Kernel | `5.10.209-android12-9-00019-g4ea09a298bb4-ab12292661` → **KMI `android12-5.10`** |
| Security patch | `2025-04-01` |
| Bootloader | locked (`ro.boot.flash.locked=1`, `verifiedbootstate=green`), no unlock token available |
| Config | `# CONFIG_MODULE_SIG is not set`, `CONFIG_XFRM=y`, `CONFIG_INET_ESP=y` |

On paper this looks like a good candidate: KMI matches a shipped `dfroot-*.ko`, unsigned modules are allowed, and the security patch is older than CVE-2026-43284.

## Symptom A — SU Manager list is always empty (blocks every current build)

Tested with **DFRoot 4.7** (`df.root`, `versionName=4.7`) and with the `mitschud/DirtyFrag` fork **v1.16 / v1.17**.
Tapping *Select a SU Manager* shows only the placeholder row — no candidates at all. With v1.16/1.17 the equivalent popup reads `No app with libksud.so found`.

The scan condition (`MainActivity.onCreate` → `ExploitRunner.hasKsud`):

```java
for (ApplicationInfo ai : pm.getInstalledApplications(0)) {
    if ((ai.flags & ApplicationInfo.FLAG_SYSTEM) != 0) continue;
    if (!ExploitRunner.hasKsud(ai)) continue;
// hasKsud: app.nativeLibraryDir != null && new File(app.nativeLibraryDir, "libksud.so").exists();
```

Ruled out, point by point:

* `QUERY_ALL_PACKAGES` is declared **and granted** — `dumpsys package df.root` → `android.permission.QUERY_ALL_PACKAGES: granted=true`.
* Both managers really do ship `libksud.so` on disk:

```
/data/app/~~CrcGMDuIjklid7Nb40w10w==/me.weishu.kernelsu-F5pi5IdJRAIT5igPFgxDcA==/lib/arm64/libksud.so   4,990,848 B
/data/app/~~LayiSk6Fp6VKWaHZng-q0A==/com.rifsxd.ksunext--n8etX1dRNELx1R2TIxqBg==/lib/arm64/libksud.so   7,059,584 B
-rwxr-xr-x system system  u:object_r:apk_data_file:s0
```

* `dumpsys package <manager>` → `extractNativeLibs=true`, `primaryCpuAbi=arm64-v8a`, `legacyNativeLibraryDir=…/lib`. Both managers were launched at least once, so `stopped=false / notLaunched=false`.
* `logcat -b all | grep avc` shows **no** denial for `apk_data_file` (the denial is presumably `dontaudit`-suppressed).
* No debuggable package is installed, so the `untrusted_app` view could not be reproduced directly (`run-as` fails for all three packages).

Reading: on HyperOS, `untrusted_app` cannot `stat()` another app's `apk_data_file` entry, so `File(nativeLibraryDir, "libksud.so").exists()` is always false and the picker can never be populated. That is a vendor restriction, not a manifest problem.

## Symptom B — a standalone build (bundled ksud) panics at trigger

For reference, `mitschud/DirtyFrag` **v1.08** was used — the last fork release that still bundles `ksud` (`assets/ksud`, 6,028,928 B), i.e. it never asks for a manager, so it does run here. Three runs, three kernel panics (`ro.boot.bootreason=kernel_panic` after each).

The run gets a long way before dying:

```
I/dfroot: ksud staged to: /data/user_de/0/df.root/ksud
I/dfroot: === exploit ===
I/dfroot: * ko android12-5.10 (12336 bytes)
I/dfroot: * patch #1 (crash_dump64 <- splicehelper, 1360 bytes)
I/dfroot: patch #1 verify OK                       <-- page-cache primitive works
I/dfroot: * patch #2 (/vendor/lib64/libbinderdebug.so <- dirtyfrag.ko, 12336 bytes) -> patched
I/dfroot: /system/lib64/libc++.so hook=0x67620 shell=0xaff90 len=532
I/dfroot: patched 544 bytes to /system/lib64/libc++.so+0xaff90
I/dfroot: patched 16 bytes to /system/lib64/libc++.so+0x67620
I/dfroot: * triggering...
F/libc (1424): Fatal signal 11 (SIGSEGV), code 2 (SEGV_ACCERR), fault addr 0x737af45040 in tid 1424 (wificond)
E/WifiNl80211Manager: Wificond died!
F/libc (1): Fatal signal 11 (SIGSEGV), code 2 (SEGV_ACCERR), fault addr 0x7f9e2f2040 in tid 1 (init), pid 1 (init)
```

Checked against the device's own ELF, in case it helps:

* `/system/lib64/libc++.so` (754,416 B) parsed with a small ELF reader: `_ZNSt3__113basic_ostreamIcNS_11char_traitsIcEEE6sentryC1ERS3_` has `st_value = 0x67620`, size 76 — **`hook=0x67620` is exactly the intended symbol**, and it lies in `.text` (`PT_LOAD off=0x4d000 filesz=0x62f90 flags=5`, R-X). Not a wrong-offset problem.
* `shell=0xaff90` is exactly the end of that RX `PT_LOAD` (`0x4d000 + 0x62f90`); the containing 4 KiB page is still mapped R-X.
* All three panics fault at an address ending in `0x040`, which matches neither `0x67620` nor `0xaff90` — the crash is *inside* the shellcode, not at the jump target.
* Ordering is the tell: a **non-init** process dies first, then `init`. Runs 1–2: `wificond` (WiFi on). Run 3 with WiFi disabled: `iptables-restore` / `ip6tables-restore` first, `init` after. Whichever process next constructs a `std::ostream` takes the trampoline and crashes inside the shellcode; the device panics only when `init` eventually takes the same path.

Upstream issue #156 (OPPO CPH2481 panic) ended with "happens when WiFi is up, mobile data works". That workaround does not help here — with WiFi off the first victim simply becomes `iptables-restore`.

## Request

1. **A ksud source that does not depend on another app's `nativeLibraryDir`.** The manager can never be picked on this ROM, but `/data/adb/ksud` *already exists* (written during the failed runs). Falling back to (a) an existing `/data/adb/ksud`, or (b) a user-selected `ksud` file, would make every current release usable on ROMs that restrict `apk_data_file` access. That alone unblocks this device.
2. **Shellcode robustness for non-`init` callers** on 5.10 `android12` GKI builds: here the trampoline is entered by ordinary processes (`wificond`, `iptables-restore`) and they fault with `SEGV_ACCERR` at `…040`; only afterwards does `init` crash. If the shellcode can detect a non-target caller and replay the original 16 bytes safely (or the hook target can be chosen per device, e.g. `libbase`), the panic would become a clean failure instead of a reboot.

Full `adb logcat -v time` captures (1.7 MB each), the `.dynsym`/`PT_LOAD` dumps and the small ELF-parsing scripts can be provided. The device is on hand and can run any test build — panics are recoverable here.
