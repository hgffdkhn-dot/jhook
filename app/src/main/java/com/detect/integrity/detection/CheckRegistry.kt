package com.detect.integrity.detection

import android.content.Context
import android.content.SharedPreferences
import androidx.preference.PreferenceManager
import com.detect.integrity.model.Category
import com.detect.integrity.model.CheckSpec
import com.detect.integrity.model.KnownLists

/**
 * 检测项注册表：所有检测项在这里登记，UI 的“项目”列表与检测引擎都从这里取。
 */
object CheckRegistry {

    fun all(context: Context): List<CheckSpec> = buildList {

        // ---------- Root / su ----------
        add(
            CheckSpec(
                "root.su_files", "su 二进制扫描", Category.ROOT,
                "扫描 ${KnownLists.SU_PATHS.size} 个已知 su 路径，并检查 PATH 中的 su", 3
            ) { RootChecks.suFiles() }
        )
        add(
            CheckSpec(
                "root.su_exec", "su 可执行性测试", Category.ROOT,
                "实际执行 su 并判断是否返回 uid=0", 3
            ) { RootChecks.suExec() }
        )
        add(
            CheckSpec(
                "root.busybox", "busybox / toybox", Category.ROOT,
                "检查是否存在 busybox（常见于已修改的系统）", 1
            ) { RootChecks.busybox() }
        )
        add(
            CheckSpec(
                "root.uid", "当前进程 UID", Category.ROOT,
                "本应用进程是否以 uid=0 运行", 1
            ) { RootChecks.shellUid() }
        )
        add(
            CheckSpec(
                "root.writable", "系统目录可写测试", Category.ROOT,
                "尝试在 /system、/vendor 等目录创建文件", 3
            ) { RootChecks.writableSystem() }
        )
        add(
            CheckSpec(
                "root.props", "Root 相关系统属性", Category.ROOT,
                "ro.secure、ro.debuggable、service.adb.root 等", 2
            ) { RootChecks.rootProps() }
        )
        add(
            CheckSpec(
                "root.dirs", "Root 常用目录", Category.ROOT,
                "/data/local、/data/adb、/su、/system/xbin 等", 2
            ) { RootChecks.rootDirs() }
        )
        add(
            CheckSpec(
                "root.initd", "init.d 启动脚本", Category.ROOT,
                "/system/etc/init.d 与 install-recovery.sh", 1
            ) { RootChecks.initD() }
        )

        // ---------- Magisk / Systemless ----------
        add(
            CheckSpec(
                "magisk.app", "Magisk 管理器", Category.MAGISK,
                "检测 Magisk / KernelSU / APatch 管理器是否安装", 3
            ) { MagiskChecks.app(context) }
        )
        add(
            CheckSpec(
                "magisk.paths", "Magisk 特征路径", Category.MAGISK,
                "扫描 ${KnownLists.MAGISK_PATHS.size} 个 systemless 方案特征路径", 3
            ) { MagiskChecks.paths() }
        )
        add(
            CheckSpec(
                "magisk.modules", "Systemless 模块目录", Category.MAGISK,
                "/data/adb/modules 下的模块", 2
            ) { MagiskChecks.modules() }
        )
        add(
            CheckSpec(
                "magisk.process", "Root 守护进程", Category.MAGISK,
                "magiskd / magiskinit / ksud / daemonsu 进程", 2
            ) { MagiskChecks.process() }
        )
        add(
            CheckSpec(
                "magisk.mounts", "Mount 特征", Category.MAGISK,
                "挂载表中的 magisk / zygisk / mirror 特征", 3
            ) { MagiskChecks.mounts() }
        )
        add(
            CheckSpec(
                "magisk.maps", "Zygisk / Riru 注入映射", Category.MAGISK,
                "/proc/self/maps 中的注入痕迹", 3
            ) { MagiskChecks.maps() }
        )
        add(
            CheckSpec(
                "magisk.env", "环境变量", Category.MAGISK,
                "MAGISK_VERSION / ZYGISK 等环境变量", 2
            ) { MagiskChecks.env() }
        )
        add(
            CheckSpec(
                "magisk.props", "getprop 关键字扫描", Category.MAGISK,
                "全量 getprop 中搜索 magisk / zygisk", 2
            ) { MagiskChecks.props() }
        )
        add(
            CheckSpec(
                "magisk.disguised", "伪装包名管理器", Category.MAGISK,
                "枚举已安装应用，找名称被伪装的 root 管理器", 2, slow = true
            ) { MagiskChecks.disguised(context) }
        )

        // ---------- 系统挂载 ----------
        add(
            CheckSpec(
                "mount.rw", "只读分区挂载属性", Category.MOUNT,
                "/system、/vendor 等是否被 rw 挂载", 3
            ) { MountChecks.systemRw() }
        )
        add(
            CheckSpec(
                "mount.overlay", "tmpfs / overlay 覆盖", Category.MOUNT,
                "系统分区是否被 tmpfs 或 overlay 覆盖", 3
            ) { MountChecks.tmpfsOverlay() }
        )
        add(
            CheckSpec(
                "mount.suspicious", "可疑挂载点", Category.MOUNT,
                "挂载点/来源中是否含 magisk、su、mirror 等关键字", 2
            ) { MountChecks.suspicious() }
        )
        add(
            CheckSpec(
                "mount.loop", "loop 设备挂载", Category.MOUNT,
                "/dev/block/loop* 挂载（模块镜像常见）", 2
            ) { MountChecks.loopDevices() }
        )
        add(
            CheckSpec(
                "mount.verity", "verity 挂载选项", Category.MOUNT,
                "挂载选项中是否启用 dm-verity", 2
            ) { MountChecks.verity() }
        )
        add(
            CheckSpec(
                "mount.table", "完整挂载表", Category.MOUNT,
                "列出 /proc/self/mountinfo 全部内容（仅信息展示，不计分）", 0
            ) { MountChecks.fullTable() }
        )

        // ---------- 风险应用 ----------
        add(
            CheckSpec(
                "pkg.root", "Root 授权管理应用", Category.PACKAGE,
                "SuperSU、KingRoot、root 隐藏类应用", 3
            ) { PackageChecks.rootManagers(context) }
        )
        add(
            CheckSpec(
                "pkg.hook", "Hook / 注入框架应用", Category.PACKAGE,
                "Xposed、LSPosed、太极、Substrate 等", 3
            ) { PackageChecks.hookApps(context) }
        )
        add(
            CheckSpec(
                "pkg.keyword", "包名关键字扫描", Category.PACKAGE,
                "已安装应用包名中是否含 magisk / root / frida 等关键字", 2
            ) { PackageChecks.keywordScan(context) }
        )
        add(
            CheckSpec(
                "pkg.shell", "shell 侧包名扫描", Category.PACKAGE,
                "通过 pm list packages 补充 PackageManager 可见性限制", 2
            ) { PackageChecks.shellPackages() }
        )
        add(
            CheckSpec(
                "pkg.unknown_src", "未知来源安装", Category.PACKAGE,
                "是否允许安装非商店应用", 1
            ) { PackageChecks.unknownSources(context) }
        )

        // ---------- Hook / 注入 ----------
        add(
            CheckSpec(
                "hook.maps", "内存映射注入特征", Category.HOOK,
                "/proc/self/maps 中的 frida / xposed / zygisk 等特征", 3
            ) { HookChecks.maps() }
        )
        add(
            CheckSpec(
                "hook.files", "Frida / 注入文件", Category.HOOK,
                "/data/local/tmp 下的 frida-server、gadget 等", 2
            ) { HookChecks.fridaFiles() }
        )
        add(
            CheckSpec(
                "hook.ports", "调试端口扫描", Category.HOOK,
                "扫描 27042/27043/27047/5555 等端口", 2, slow = true
            ) { HookChecks.ports() }
        )
        add(
            CheckSpec(
                "hook.libs", "Riru / Zygisk 注入库", Category.HOOK,
                "libriru.so、libzygisk.so 等", 2
            ) { HookChecks.riruLibs() }
        )
        add(
            CheckSpec(
                "hook.preload", "LD_PRELOAD 注入", Category.HOOK,
                "检查预加载 / 注入类环境变量", 2
            ) { HookChecks.preload() }
        )
        add(
            CheckSpec(
                "hook.proc", "进程命令行扫描", Category.HOOK,
                "遍历 /proc/*/cmdline 找注入相关进程", 2
            ) { HookChecks.procScan() }
        )

        // ---------- 系统完整性 ----------
        add(
            CheckSpec(
                "sys.vboot", "Verified Boot 状态", Category.INTEGRITY,
                "green / orange / yellow / red", 3
            ) { SystemChecks.verifiedBoot() }
        )
        add(
            CheckSpec(
                "sys.vbmeta", "vbmeta 设备状态", Category.INTEGRITY,
                "locked / unlocked", 3
            ) { SystemChecks.vbmetaState() }
        )
        add(
            CheckSpec(
                "sys.locked", "bootloader 锁定状态", Category.INTEGRITY,
                "ro.boot.flash.locked / ro.bootloader", 3
            ) { SystemChecks.flashLocked() }
        )
        add(
            CheckSpec(
                "sys.verity", "dm-verity 模式", Category.INTEGRITY,
                "enforcing / eio / disabled", 2
            ) { SystemChecks.dmVerity() }
        )
        add(
            CheckSpec(
                "sys.selinux", "SELinux 模式", Category.INTEGRITY,
                "Enforcing / Permissive", 2
            ) { SystemChecks.selinux() }
        )
        add(
            CheckSpec(
                "sys.tags", "构建签名密钥", Category.INTEGRITY,
                "release-keys / test-keys / dev-keys", 3
            ) { SystemChecks.buildTags() }
        )
        add(
            CheckSpec(
                "sys.type", "构建类型", Category.INTEGRITY,
                "user / userdebug / eng", 2
            ) { SystemChecks.buildType() }
        )
        add(
            CheckSpec(
                "sys.otacert", "OTA 公钥证书", Category.INTEGRITY,
                "/system/etc/security/otacerts.zip 内容", 2
            ) { SystemChecks.otaCerts() }
        )
        add(
            CheckSpec(
                "sys.platform_sig", "系统框架签名", Category.INTEGRITY,
                "android 包的签名证书指纹与主体", 2
            ) { SystemChecks.platformSignature(context) }
        )
        add(
            CheckSpec(
                "sys.oem_unlock", "OEM 解锁开关", Category.INTEGRITY,
                "Settings.Global.OEM_UNLOCK_ALLOWED", 1
            ) { SystemChecks.oemUnlock(context) }
        )
        add(
            CheckSpec(
                "sys.rollback", "回滚保护索引", Category.INTEGRITY,
                "rollback_index、slot_suffix、vbmeta digest", 1
            ) { SystemChecks.rollback() }
        )
        add(
            CheckSpec(
                "sys.version", "版本与补丁信息", Category.INTEGRITY,
                "Android 版本、安全补丁、内核、ABI", 0
            ) { SystemChecks.versionInfo() }
        )
        add(
            CheckSpec(
                "sys.bootchain", "启动链路属性", Category.INTEGRITY,
                "bootloader、硬件版本、首发 API 等", 0
            ) { SystemChecks.bootChain() }
        )
        add(
            CheckSpec(
                "sys.files", "系统目录文件扫描", Category.INTEGRITY,
                "在 /system/bin、/sbin 等目录搜索 su、magisk、frida 等文件名", 2, slow = true
            ) { SystemChecks.fileScan() }
        )

        // ---------- 谷歌证书与 GMS ----------
        add(
            CheckSpec(
                "gms.available", "Google Play 服务可用性", Category.GOOGLE_CERT,
                "GMS 是否安装且可用", 1
            ) { GoogleChecks.availability(context) }
        )
        add(
            CheckSpec(
                "gms.signature", "GMS 签名证书校验", Category.GOOGLE_CERT,
                "校验 com.google.android.gms 的签名主体与指纹", 2
            ) { GoogleChecks.gmsSignature(context) }
        )
        add(
            CheckSpec(
                "gms.vending", "应用商店签名校验", Category.GOOGLE_CERT,
                "校验 com.android.vending 的签名主体与指纹", 2
            ) { GoogleChecks.vendingSignature(context) }
        )
        add(
            CheckSpec(
                "gms.truststore", "系统信任库 Google 根证书", Category.GOOGLE_CERT,
                "AndroidCAStore 中的 GTS / Google Internet Authority 根证书", 2
            ) { GoogleChecks.trustStore() }
        )
        add(
            CheckSpec(
                "gms.cacerts", "系统 CA 目录完整性", Category.GOOGLE_CERT,
                "/system/etc/security/cacerts 证书能否正常解析", 2
            ) { GoogleChecks.caDirectory() }
        )
        add(
            CheckSpec(
                "gms.apex", "APEX / 证书目录", Category.GOOGLE_CERT,
                "conscrypt、art、runtime 等 APEX 是否存在", 1
            ) { GoogleChecks.apexConscrypt() }
        )
        add(
            CheckSpec(
                "gms.otazip", "OTA 证书压缩包", Category.GOOGLE_CERT,
                "otacerts.zip 内容清单", 0
            ) { GoogleChecks.otaZip() }
        )

        // ---------- 应用自身完整性 ----------
        add(
            CheckSpec(
                "self.signature", "自身签名指纹", Category.SIGNATURE,
                "与设置中配置的期望签名比对，识别二次打包", 2
            ) { SelfChecks.signature(context, expectedSignature(context)) }
        )
        add(
            CheckSpec(
                "self.installer", "安装来源", Category.SIGNATURE,
                "是否来自 Google Play", 1
            ) { SelfChecks.installer(context) }
        )
        add(
            CheckSpec(
                "self.debuggable", "可调试标志", Category.SIGNATURE,
                "FLAG_DEBUGGABLE / BuildConfig.DEBUG", 2
            ) { SelfChecks.debuggable(context) }
        )
        add(
            CheckSpec(
                "self.path", "APK 安装路径", Category.SIGNATURE,
                "sourceDir / nativeLibraryDir 是否异常", 1
            ) { SelfChecks.apkPath(context) }
        )

        // ---------- 调试与开发者选项 ----------
        add(
            CheckSpec(
                "dbg.attached", "调试器附加", Category.DEBUGGER,
                "Debug.isDebuggerConnected", 2
            ) { DebugChecks.attached() }
        )
        add(
            CheckSpec(
                "dbg.tracer", "ptrace 跟踪检测", Category.DEBUGGER,
                "/proc/self/status 的 TracerPid", 2
            ) { DebugChecks.tracerPid() }
        )
        add(
            CheckSpec(
                "dbg.adb", "ADB 调试开关", Category.DEBUGGER,
                "USB 调试 / 无线调试是否开启", 1
            ) { DebugChecks.adb(context) }
        )
        add(
            CheckSpec(
                "dbg.dev", "开发者选项与 root adbd", Category.DEBUGGER,
                "开发者选项、adbd 是否以 root 运行", 1
            ) { DebugChecks.devOptions(context) }
        )
        add(
            CheckSpec(
                "dbg.automation", "自动化测试环境", Category.DEBUGGER,
                "isUserAMonkey / ro.test_harness", 1
            ) { DebugChecks.automation(context) }
        )

        // ---------- 模拟器 ----------
        add(
            CheckSpec(
                "emu.build", "Build 字段特征", Category.EMULATOR,
                "FINGERPRINT / MODEL / HARDWARE 等是否含模拟器标识", 2
            ) { EmulatorChecks.buildFields() }
        )
        add(
            CheckSpec(
                "emu.props", "QEMU 属性", Category.EMULATOR,
                "ro.kernel.qemu、ro.hardware=goldfish 等", 2
            ) { EmulatorChecks.qemuProps() }
        )
        add(
            CheckSpec(
                "emu.files", "模拟器设备文件", Category.EMULATOR,
                "/dev/qemu_pipe、qemud socket 等", 2
            ) { EmulatorChecks.qemuFiles() }
        )
        add(
            CheckSpec(
                "emu.features", "硬件特性缺失", Category.EMULATOR,
                "电话、蓝牙、GPS、陀螺仪等特性", 1
            ) { EmulatorChecks.features(context) }
        )
        add(
            CheckSpec(
                "emu.sensors", "传感器列表", Category.EMULATOR,
                "无传感器的设备多为模拟器", 1
            ) { EmulatorChecks.sensors(context) }
        )

        // ---------- Play Integrity ----------
        add(
            CheckSpec(
                "pi.verdict", "Play Integrity 判定", Category.PLAY_INTEGRITY,
                "Google 官方设备完整性认证（需 GMS 与云端项目号）", 3, needsPlay = true
            ) {
                val prefs = PreferenceManager.getDefaultSharedPreferences(context)
                PlayIntegrityCheck.run(
                    context = context,
                    enabled = prefs.getBoolean("pref_enable_pi", false),
                    cloudProject = prefs.getString("pref_cloud_project", "") ?: "",
                    endpoint = prefs.getString("pref_pi_endpoint", "") ?: ""
                )
            }
        )
    }

    /** 根据设置过滤出本次要执行的检测项 */
    fun enabled(context: Context): List<CheckSpec> {
        val prefs: SharedPreferences = PreferenceManager.getDefaultSharedPreferences(context)
        val skipSlow = prefs.getBoolean("pref_skip_slow", false)
        val enablePi = prefs.getBoolean("pref_enable_pi", false)
        val gmsCheck = prefs.getBoolean("pref_gms_check", true)
        return all(context).filter { spec ->
            if (spec.slow && skipSlow) return@filter false
            if (spec.needsPlay && !enablePi) return@filter false
            if (spec.category == Category.GOOGLE_CERT && !gmsCheck) return@filter false
            true
        }
    }

    private fun expectedSignature(context: Context): String =
        PreferenceManager.getDefaultSharedPreferences(context)
            .getString("pref_expected_sig", "") ?: ""
}
