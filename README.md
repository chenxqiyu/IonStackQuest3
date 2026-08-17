```
adb reboot bootloader

sideload update

adb sideload "I:\models\q3_52168470043600520.zip"

使用ionstack.conf.example到ionstack.conf

root成功
```

```
adb shell getprop | grep -E "ro.build.version|ro.product.model"
[ro.build.version.all_codenames]: [REL]
[ro.build.version.base_os]: []
[ro.build.version.codename]: [REL]
[ro.build.version.incremental]: [52168470043600520]
[ro.build.version.known_codenames]: [Base,Base11,Cupcake,Donut,Eclair,Eclair01,EclairMr1,Froyo,Gingerbread,GingerbreadMr1,Honeycomb,HoneycombMr1,HoneycombMr2,IceCreamSandwich,IceCreamSandwichMr1,JellyBean,JellyBeanMr1,JellyBeanMr2,Kitkat,KitkatWatch,Lollipop,LollipopMr1,M,N,NMr1,O,OMr1,P,Q,R,S,Sv2,Tiramisu,UpsideDownCake,VanillaIceCream]
[ro.build.version.min_supported_target_sdk]: [28]
[ro.build.version.preview_sdk]: [0]
[ro.build.version.preview_sdk_fingerprint]: [REL]
[ro.build.version.release]: [14]
[ro.build.version.release_or_codename]: [14]
[ro.build.version.release_or_preview_display]: [14]
[ro.build.version.sdk]: [34]
[ro.build.version.security_patch]: [2026-05-01]
[ro.product.model]: [Quest 3]
[ro.product.model_for_attestation]: []
```

# IonStack exploit for Meta Quest 3

Root exploit for Meta Quest 3, adapted from IonStack (CVE-2026-43499) in [CyberMeowfia](https://github.com/NebuSec/CyberMeowfia).

# Use at your own risk!!!


## Device Info

| Item | Value |
|------|-------|
| Device | Meta Quest 3 |
| Architecture | aarch64 |
| Kernel | `Linux localhost 5.10.240-g69827d40d782 #1 SMP PREEMPT Mon Jun 1 13:01:51 PDT 2026 aarch64 Toybox` |
| Incremental | `52168470043600520` |
| mm_struct | order-2 |

Kernels of similar versions are likely to work without re-adaptation.

## Update
Meta has fixed CVE-2026-43499 in Quest 3 incremental build [`52345320040100520`](https://github.com/facebookincubator/oculus-linux-kernel/commit/ab1c46013e3f279a9d033a1c3cf0542c1d32d46c) and Quest 3s incremental build [`3697600032300610`](https://github.com/facebookincubator/oculus-linux-kernel/commit/6d15b6aa864d26f742466c66ad3c2929b15ba786). Devices running these builds or later are no longer vulnerable to this exploit.

## Usage

### 1. Obtain ionstack.conf

#### Pre-adapted version

If your kernel version matches the device info above, skip ionstack.conf.

#### Unadapted version (generate via GitHub Actions)

If your firmware version differs, you can auto-generate the config via GitHub Actions:

1. **Fork this repository.**
2. **Get your device's incremental number** via adb:
   ```sh
   adb shell getprop ro.build.version.incremental
   ```
3. **Download the matching firmware.** If you don't know the download URL, use the following (replace `{incremental}` with the value from the previous step):

   Quest3
   ```
   https://files.cocaine.trade/firmware/meta/Quest%203/q3_{incremental}.zip
   ```
   Quest3s
   ```
   https://files.cocaine.trade/firmware/meta/Quest%203S/q3s_{incremental}.zip
   ```

4. **Run the Action:** In your forked repo, run the `generate-ionstack-config` workflow, fill in the firmware download URL, wait for completion, and download the generated `ionstack.conf`.

### 2. Obtain preload

#### Option A: Download from Releases

Download the precompiled `preload` binary from the [Releases](../../releases) page.

#### Option B: Build from source

Requires Android NDK. The recommended version is:
```
https://dl.google.com/android/repository/android-ndk-r29-linux.zip
```

After installing the NDK, build from the project directory:
```sh
make
```

### 3. Deploy and run

Push files to the device and execute:

```sh
# Push preload
adb push preload /data/local/tmp/

# Push ionstack.conf if your incremental differs from 52168470043600520
# (skip this step if your device matches the default incremental above)
adb push ionstack.conf /data/local/tmp/

# Make executable and run
adb shell chmod +x /data/local/tmp/preload
adb shell /data/local/tmp/preload

# Optional. If you want to run commands like pm directly in root shell without root manager.
runcon u:r:shell:s0 /system/bin/sh
```

If everything works, you should get a root shell.

## Notes

- Do NOT modify any system partition, especially do not run any manager install commands. This can brick your device.
- Running the exploit may cause the Quest to hang. If this happens, long-press the power button to force reboot.
- The exploit has the highest success rate right after boot. A fresh reboot is recommended before running.



## Credits

- [CyberMeowfia](https://github.com/NebuSec/CyberMeowfia) — original IonStack (CVE-2026-43499) exploit
- [@zhuowei/cheese](https://github.com/zhuowei/cheese) — key adaptation info
- [kernelsnitch](https://github.com/lukasmaar/kernelsnitch) — kernel module
- [@ptrpaws/cocaine.trade](https://github.com/ptrpaws/cocaine.trade) — firmware links
