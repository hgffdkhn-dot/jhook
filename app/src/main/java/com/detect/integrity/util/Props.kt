package com.detect.integrity.util

/**
 * 系统属性读取：优先反射 android.os.SystemProperties，失败回落到 build.prop 文本解析。
 */
object Props {

    private const val TAG = "Props"

    private val spGet = try {
        val cls = Class.forName("android.os.SystemProperties")
        cls.getMethod("get", String::class.java)
    } catch (_: Exception) {
        null
    }

    private val cache = HashMap<String, String>()
    private var propFilesLoaded = false

    private val PROP_FILES = listOf(
        "/system/build.prop",
        "/system_ext/build.prop",
        "/vendor/build.prop",
        "/product/build.prop",
        "/system/product/build.prop",
        "/odm/build.prop",
        "/vendor/default.prop",
        "/default.prop",
        "/system/default.prop",
        "/system/etc/prop.default",
        "/prop.default",
        "/data/local.prop"
    )

    private fun loadPropFiles() {
        if (propFilesLoaded) return
        propFilesLoaded = true
        for (file in PROP_FILES) {
            for (line in Fs.readLines(file)) {
                val t = line.trim()
                if (t.isEmpty() || t.startsWith("#")) continue
                val i = t.indexOf('=')
                if (i <= 0) continue
                val k = t.substring(0, i).trim()
                val v = t.substring(i + 1).trim()
                if (!cache.containsKey(k)) cache[k] = v
            }
        }
    }

    fun get(key: String, def: String = ""): String {
        cache[key]?.let { if (it.isNotEmpty()) return it }
        try {
            val v = spGet?.invoke(null, key) as? String
            if (!v.isNullOrEmpty()) {
                cache[key] = v
                return v
            }
        } catch (_: Exception) {
        }
        loadPropFiles()
        val v = cache[key]
        if (!v.isNullOrEmpty()) return v
        val shellV = Shell.out("getprop $key 2>/dev/null", 1200)
        if (shellV.isNotEmpty() && shellV != key) {
            cache[key] = shellV
            return shellV
        }
        return def
    }

    /** 属性是否等于某个值（忽略大小写） */
    fun isValue(key: String, vararg values: String): Boolean {
        val v = get(key)
        if (v.isEmpty()) return false
        return values.any { it.equals(v, ignoreCase = true) }
    }

    /** 内核命令行参数（androidboot.xxx） */
    fun cmdline(): Map<String, String> {
        val raw = Fs.readText("/proc/cmdline")
        val map = LinkedHashMap<String, String>()
        raw.split(Regex("\\s+")).forEach { token ->
            val i = token.indexOf('=')
            if (i > 0) map[token.substring(0, i)] = token.substring(i + 1)
        }
        return map
    }

    /** 组合读取：属性 -> /proc/cmdline 里的 androidboot. 同名项 */
    fun getOrBoot(key: String): String {
        val v = get(key)
        if (v.isNotEmpty()) return v
        return cmdline()["androidboot.$key"] ?: ""
    }
}
