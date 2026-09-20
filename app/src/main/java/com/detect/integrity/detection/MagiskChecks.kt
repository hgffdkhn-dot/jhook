package com.detect.integrity.detection

import android.content.Context
import com.detect.integrity.model.KnownLists
import com.detect.integrity.model.Outcome
import com.detect.integrity.model.Status
import com.detect.integrity.util.Fs
import com.detect.integrity.util.Pkg
import com.detect.integrity.util.Proc
import com.detect.integrity.util.Shell

/**
 * Magisk / KernelSU / APatch 等 systemless 方案检测
 */
object MagiskChecks {

    /** 1. Magisk 管理器 App */
    fun app(context: Context): Outcome {
        val installed = Pkg.installedFrom(context, KnownLists.MAGISK_PACKAGES)
        val evidence = installed.map { "已安装: $it (${Pkg.versionName(context, it)})" }
            .ifEmpty { KnownLists.MAGISK_PACKAGES.map { "未安装: $it" } }
        return if (installed.isNotEmpty()) {
            Outcome(Status.DANGER, "发现 ${installed.size} 个 Magisk / root 管理器应用", evidence)
        } else {
            Outcome(Status.PASS, "未发现 Magisk 管理器", evidence)
        }
    }

    /** 2. Magisk 特征路径 */
    fun paths(): Outcome {
        val found = KnownLists.MAGISK_PATHS.filter { Fs.exists(it) }
        val evidence = found.map { "路径存在: $it" }
            .ifEmpty { listOf("已扫描 ${KnownLists.MAGISK_PATHS.size} 个已知特征路径，均未命中") }
        val core = found.filter {
            it.contains("magisk") || it.contains("ksu") || it.contains("apatch") || it.contains("apd")
        }
        return when {
            core.isNotEmpty() -> Outcome(Status.DANGER, "发现 ${core.size} 个 Magisk / root 方案特征路径", evidence)
            found.any { it.contains("zygisk") } -> Outcome(Status.DANGER, "发现 Zygisk 设备节点", evidence)
            found.isNotEmpty() -> Outcome(Status.WARN, "发现 ${found.size} 个可疑路径", evidence)
            else -> Outcome(Status.PASS, "未发现 Magisk 特征路径", evidence)
        }
    }

    /** 3. 模块目录内容 */
    fun modules(): Outcome {
        val base = "/data/adb/modules"
        val evidence = mutableListOf<String>()
        if (!Fs.exists(base)) {
            return Outcome(Status.PASS, "无模块目录", listOf("$base 不存在"))
        }
        val mods = Fs.list(base)
        evidence += "$base -> 存在，${mods.size} 项"
        mods.forEach { evidence += "  模块: $it" }
        val ksu = Fs.list("/data/adb/ksu")
        if (ksu.isNotEmpty()) evidence += "/data/adb/ksu -> ${ksu.joinToString()}"
        return Outcome(Status.DANGER, "发现 ${mods.size} 个 systemless 模块", evidence)
    }

    /** 4. magiskd / magiskinit 进程 */
    fun process(): Outcome {
        val procs = Proc.hasProcess("magiskd", "magiskinit", "magisk", "ksud", "apd", "su", "daemonsu")
        val cmdline = Proc.procCmdlineMatch("magisk", "ksud", "apd", "daemonsu")
        val evidence = mutableListOf<String>()
        if (procs.isEmpty()) {
            evidence += "ps 中未发现相关进程"
        } else {
            evidence += procs.map { "ps: $it" }
        }
        if (cmdline.isNotEmpty()) evidence += cmdline.map { "/proc: $it" }
        val hit = procs.isNotEmpty() || cmdline.isNotEmpty()
        return if (hit) {
            Outcome(Status.DANGER, "发现 ${procs.size + cmdline.size} 个 root 守护进程痕迹", evidence)
        } else {
            Outcome(Status.PASS, "未发现 magiskd / magiskinit 等进程", evidence)
        }
    }

    /** 5. 挂载特征（tmpfs / overlay 覆盖系统目录） */
    fun mounts(): Outcome {
        val mounts = Proc.mounts()
        val keywords = listOf("magisk", ".magisk", "zygisk", "worker", "mirror", "sbin", "core", "ksu")
        val hit = mounts.filter { m ->
            val s = m.raw.lowercase()
            keywords.any { s.contains(it) } && (m.fs.equals("tmpfs", true) || m.fs.equals("overlay", true) || m.target == "/sbin" || m.target == "/")
        }
        val evidence = hit.map { m -> m.raw.take(200) }
            .ifEmpty { listOf("挂载表中未发现 magisk / zygisk / mirror 特征（共 ${mounts.size} 条挂载）") }
        return if (hit.isNotEmpty()) {
            Outcome(Status.DANGER, "挂载表中发现 ${hit.size} 条 systemless 特征", evidence)
        } else {
            Outcome(Status.PASS, "挂载表无 Magisk 特征", evidence)
        }
    }

    /** 6. 内存映射注入特征 */
    fun maps(): Outcome {
        val injKeywords = listOf("zygisk", "magisk", "riru", "libriru", "memfd:zygisk", "libzygisk")
        val hits = Proc.mapsMatch(*injKeywords.toTypedArray())
        val evidence = hits.take(20).map { it.take(200) }
            .ifEmpty { listOf("/proc/self/maps 中未发现 zygisk / riru / magisk 映射") }
        return if (hits.isNotEmpty()) {
            Outcome(Status.DANGER, "进程内存映射中发现 ${hits.size} 条注入特征", evidence)
        } else {
            Outcome(Status.PASS, "未发现注入映射", evidence)
        }
    }

    /** 7. 环境变量 */
    fun env(): Outcome {
        val env = Proc.environ()
        val systemEnv = listOf("MAGISK_VERSION", "MAGISK_VER_CODE", "ZYGISK_ENABLED", "KSU", "APATCH")
            .mapNotNull { k -> System.getenv(k)?.let { "$k=$it" } }
        val suspicious = env.filter { (k, v) ->
            val s = (k + "=" + v).lowercase()
            s.contains("magisk") || s.contains("zygisk") || s.contains("riru") ||
                s.contains("ksu") || s.contains("apatch") || s.contains("frida")
        }.map { "${it.key}=${it.value}" }
        val evidence = mutableListOf<String>()
        evidence += "系统环境: ${systemEnv.ifEmpty { listOf("无") }.joinToString(", ")}"
        evidence += "进程环境: ${suspicious.ifEmpty { listOf("无 Magisk / Zygisk 相关变量") }.joinToString(", ")}"
        val hit = systemEnv.isNotEmpty() || suspicious.isNotEmpty()
        return if (hit) {
            Outcome(Status.DANGER, "环境变量中存在 Magisk / Zygisk 痕迹", evidence)
        } else {
            Outcome(Status.PASS, "环境变量正常", evidence)
        }
    }

    /** 8. getprop 全量扫描 magisk 关键字 */
    fun props(): Outcome {
        val all = Shell.out("getprop 2>/dev/null", 3000)
        val hits = all.lines().filter { it.contains("magisk", true) || it.contains("zygisk", true) }
        val evidence = hits.take(20).ifEmpty { listOf("getprop 输出中无 magisk / zygisk 关键字") }
        return if (hits.isNotEmpty()) {
            Outcome(Status.WARN, "系统属性中发现 ${hits.size} 条 Magisk 相关项", evidence)
        } else {
            Outcome(Status.PASS, "系统属性无 Magisk 关键字", evidence)
        }
    }

    /** 9. 伪装包名 / 随机包名检测（耗时） */
    fun disguised(context: Context): Outcome {
        val names = Pkg.installedNames(context)
        if (names.isEmpty()) {
            return Outcome(Status.INFO, "无法枚举已安装应用（受包可见性限制）", listOf("请在系统设置中允许，或改用 shell 方式"))
        }
        val pm = context.packageManager
        val evidence = mutableListOf<String>()
        val suspects = mutableListOf<String>()
        for (name in names) {
            val label = try {
                pm.getApplicationInfo(name, 0).loadLabel(pm).toString()
            } catch (_: Exception) {
                continue
            }
            if (label.contains("magisk", true) || label.contains("kernelsu", true) || label.contains("apatch", true)) {
                if (!KnownLists.MAGISK_PACKAGES.contains(name)) {
                    suspects += "$name ($label)"
                }
            }
        }
        evidence += "已枚举 ${names.size} 个包名"
        evidence += suspects.ifEmpty { listOf("未发现名称伪装成随机串的 Magisk 管理器") }
        return if (suspects.isNotEmpty()) {
            Outcome(Status.DANGER, "发现 ${suspects.size} 个伪装包名的 root 管理器", evidence)
        } else {
            Outcome(Status.PASS, "未发现伪装包名", evidence)
        }
    }
}
