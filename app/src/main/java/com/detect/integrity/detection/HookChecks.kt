package com.detect.integrity.detection

import com.detect.integrity.model.KnownLists
import com.detect.integrity.model.Outcome
import com.detect.integrity.model.Status
import com.detect.integrity.util.Fs
import com.detect.integrity.util.Proc
import com.detect.integrity.util.Shell
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import java.net.InetSocketAddress
import java.net.Socket

/**
 * 注入与 Hook 检测
 */
object HookChecks {

    /** 1. /proc/self/maps 注入特征 */
    fun maps(): Outcome {
        val hits = Proc.mapsMatch(*KnownLists.MAPS_KEYWORDS.toTypedArray())
        val evidence = hits.take(25).map { it.take(200) }
            .ifEmpty { listOf("/proc/self/maps 中未命中 ${KnownLists.MAPS_KEYWORDS.size} 个注入关键字") }
        val strong = hits.filter {
            val s = it.lowercase()
            s.contains("frida") || s.contains("xposed") || s.contains("zygisk") ||
                s.contains("libriru") || s.contains("substrate")
        }
        return when {
            strong.isNotEmpty() -> Outcome(Status.DANGER, "内存映射中发现 ${strong.size} 条明确注入特征", evidence)
            hits.isNotEmpty() -> Outcome(Status.WARN, "发现 ${hits.size} 处可疑映射", evidence)
            else -> Outcome(Status.PASS, "未发现注入特征", evidence)
        }
    }

    /** 2. Frida / 注入相关文件 */
    fun fridaFiles(): Outcome {
        val paths = listOf(
            "/data/local/tmp/frida-server", "/data/local/tmp/frida-server64",
            "/data/local/tmp/frida", "/data/local/tmp/re.frida.server",
            "/data/local/tmp/load.dex", "/data/local/tmp/inject",
            "/data/local/tmp/libfrida-gadget.so", "/data/local/tmp/gadget.so",
            "/data/local/tmp/android_server", "/data/local/tmp/minicap",
            "/system/lib/libfrida-gadget.so", "/system/lib64/libfrida-gadget.so"
        )
        val found = paths.filter { Fs.exists(it) }
        val tmpList = Fs.list("/data/local/tmp")
        val evidence = found.map { "文件存在: $it" } +
            listOf("/data/local/tmp 内容: ${tmpList.joinToString().ifEmpty { "空或不可读" }}")
        return if (found.isNotEmpty()) {
            Outcome(Status.DANGER, "发现 ${found.size} 个注入/调试相关文件", evidence)
        } else {
            Outcome(Status.PASS, "未发现 Frida / 注入文件", evidence)
        }
    }

    /** 3. 调试端口扫描（耗时） */
    suspend fun ports(): Outcome = withContext(Dispatchers.IO) {
        val open = mutableListOf<String>()
        val evidence = mutableListOf<String>()
        for (port in KnownLists.DEBUG_PORTS) {
            val opened = try {
                Socket().use { s ->
                    s.connect(InetSocketAddress("127.0.0.1", port), 300)
                    true
                }
            } catch (_: Exception) {
                false
            }
            evidence += "127.0.0.1:$port -> ${if (opened) "开放" else "关闭"}"
            if (opened) open += "$port"
        }
        val fridaPorts = listOf(27042, 27043, 27047)
        val hitFrida = open.map { it.toInt() }.any { it in fridaPorts }
        return@withContext when {
            hitFrida -> Outcome(Status.DANGER, "检测到 Frida 监听端口 ${open.joinToString()}", evidence)
            open.isNotEmpty() -> Outcome(Status.WARN, "开放端口: ${open.joinToString()}", evidence)
            else -> Outcome(Status.PASS, "未发现调试/注入监听端口", evidence)
        }
    }

    /** 4. Riru / Zygisk 注入库 */
    fun riruLibs(): Outcome {
        val paths = listOf(
            "/system/lib/libriru.so", "/system/lib64/libriru.so",
            "/system/lib/libriruloader.so", "/system/lib64/libriruloader.so",
            "/system/lib/libzygisk.so", "/system/lib64/libzygisk.so",
            "/system/lib/libmemtrack_proxy.so", "/system/lib64/libmemtrack_proxy.so",
            "/data/adb/modules/riru-core", "/data/adb/modules/zygisk_lsposed"
        )
        val found = paths.filter { Fs.exists(it) }
        val evidence = found.map { "文件存在: $it" }
            .ifEmpty { listOf("未发现 Riru / Zygisk 注入库") }
        return if (found.isNotEmpty()) {
            Outcome(Status.DANGER, "发现 ${found.size} 个注入库/模块", evidence)
        } else {
            Outcome(Status.PASS, "无 Riru / Zygisk 注入库", evidence)
        }
    }

    /** 5. LD_PRELOAD / LD_LIBRARY_PATH */
    fun preload(): Outcome {
        val env = Proc.environ()
        val keys = listOf("LD_PRELOAD", "LD_LIBRARY_PATH", "CLASSPATH_EXTRA", "DEXPOSED")
        val hit = env.filter { (k, _) -> keys.any { it.equals(k, true) } || k.lowercase().contains("inject") }
        val systemEnv = keys.mapNotNull { k -> System.getenv(k)?.let { "$k=$it" } }
        val evidence = mutableListOf<String>()
        evidence += "进程环境: ${hit.entries.joinToString(", ").ifEmpty { "无" }}"
        evidence += "System.getenv: ${systemEnv.joinToString(", ").ifEmpty { "无" }}"
        val all = hit.isNotEmpty() || systemEnv.isNotEmpty()
        return if (all) {
            Outcome(Status.WARN, "存在预加载 / 注入类环境变量", evidence)
        } else {
            Outcome(Status.PASS, "无 LD_PRELOAD 等注入变量", evidence)
        }
    }

    /** 6. /proc 进程名扫描 */
    fun procScan(): Outcome {
        val hits = Proc.procCmdlineMatch("frida", "xposed", "lsposed", "riru", "inject", "hook", "gadget")
        val evidence = hits.take(20).ifEmpty { listOf("/proc 中未发现注入相关进程") }
        return if (hits.isNotEmpty()) {
            Outcome(Status.WARN, "发现 ${hits.size} 个可疑进程", evidence)
        } else {
            Outcome(Status.PASS, "无注入相关进程", evidence)
        }
    }
}
