package com.detect.integrity.util

/**
 * /proc 读取工具：挂载表、内存映射、进程状态、环境变量等。
 */
object Proc {

    data class Mount(
        val source: String,
        val target: String,
        val fs: String,
        val options: List<String>,
        val raw: String
    ) {
        fun hasOption(opt: String): Boolean = options.any { it.equals(opt, ignoreCase = true) }
        val isRw: Boolean get() = hasOption("rw")
    }

    /** 优先解析 /proc/self/mountinfo（信息最全），失败回落 /proc/self/mounts */
    fun mounts(): List<Mount> {
        val info = Fs.readLines("/proc/self/mountinfo")
        if (info.isNotEmpty()) return info.mapNotNull { parseMountInfo(it) }
        return Fs.readLines("/proc/self/mounts").mapNotNull { parseMountsOld(it) }
            .ifEmpty { Fs.readLines("/proc/mounts").mapNotNull { parseMountsOld(it) } }
    }

    private fun parseMountInfo(line: String): Mount? {
        val t = line.trim()
        if (t.isEmpty()) return null
        val p = t.split(Regex("\\s+"))
        if (p.size < 7) return null
        val target = p[4]
        val options = p[5].split(",").filter { it.isNotEmpty() }
        val dash = p.indexOf("-")
        if (dash >= 0 && p.size > dash + 2) {
            return Mount(p[dash + 2], target, p[dash + 1], options, t)
        }
        return Mount("", target, "", options, t)
    }

    private fun parseMountsOld(line: String): Mount? {
        val t = line.trim()
        if (t.isEmpty()) return null
        val p = t.split(Regex("\\s+"))
        if (p.size < 4) return null
        return Mount(p[0], p[1], p[2], p[3].split(",").filter { it.isNotEmpty() }, t)
    }

    /** /proc/self/maps 中包含指定关键字的行 */
    fun mapsMatch(vararg keywords: String): List<String> {
        val lines = Fs.readLines("/proc/self/maps")
        if (lines.isEmpty()) return emptyList()
        val lower = keywords.map { it.lowercase() }
        return lines.filter { l ->
            val s = l.lowercase()
            lower.any { s.contains(it) }
        }.map { it.trim() }
    }

    fun maps(): List<String> = Fs.readLines("/proc/self/maps")

    /** /proc/self/status 中某个字段，例如 TracerPid */
    fun statusField(name: String): String? {
        for (line in Fs.readLines("/proc/self/status")) {
            val i = line.indexOf(':')
            if (i > 0 && line.substring(0, i).trim().equals(name, ignoreCase = true)) {
                return line.substring(i + 1).trim()
            }
        }
        return null
    }

    /** 当前进程环境变量 */
    fun environ(): Map<String, String> {
        val raw = Fs.readText("/proc/self/environ")
        if (raw.isEmpty()) return emptyMap()
        val map = LinkedHashMap<String, String>()
        raw.split('\u0000').forEach { e ->
            val i = e.indexOf('=')
            if (i > 0) map[e.substring(0, i)] = e.substring(i + 1)
        }
        return map
    }

    /** ps 输出（Android 8+ 用 ps -A -o NAME,CMD，老版本回落 ps） */
    fun processes(): List<String> {
        var out = Shell.out("ps -A -o NAME,CMD 2>/dev/null || ps -A 2>/dev/null || ps 2>/dev/null", 2500)
        if (out.isBlank()) return emptyList()
        return out.split("\n").map { it.trim() }.filter { it.isNotEmpty() }
    }

    fun hasProcess(vararg names: String): List<String> {
        val procs = processes()
        if (procs.isEmpty()) return emptyList()
        val lower = names.map { it.lowercase() }
        return procs.filter { p ->
            val s = p.lowercase()
            lower.any { s.contains(it) }
        }.distinct()
    }

    /** 扫描 /proc 下的进程 cmdline，比 ps 更底层 */
    fun procCmdlineMatch(vararg names: String): List<String> {
        val found = LinkedHashSet<String>()
        val pids = Fs.list("/proc").filter { it.all { c -> c.isDigit() } }
        for (pid in pids) {
            val line = Fs.readText("/proc/$pid/cmdline").replace('\u0000', ' ').trim()
            if (line.isEmpty()) continue
            val lower = line.lowercase()
            if (names.any { lower.contains(it.lowercase()) }) {
                found.add("$pid: $line")
            }
        }
        return found.toList()
    }
}
