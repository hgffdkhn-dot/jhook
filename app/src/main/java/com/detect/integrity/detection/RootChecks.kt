package com.detect.integrity.detection

import com.detect.integrity.model.KnownLists
import com.detect.integrity.model.Outcome
import com.detect.integrity.model.Status
import com.detect.integrity.util.Fs
import com.detect.integrity.util.Props
import com.detect.integrity.util.Shell

/**
 * Root / su 相关检测
 */
object RootChecks {

    /** 1. 扫描常见 su 路径 */
    fun suFiles(): Outcome {
        val found = KnownLists.SU_PATHS.filter { Fs.exists(it) }
        val which = Shell.out(
            "command -v su 2>/dev/null; which su 2>/dev/null; ls -l /system/bin/su /system/xbin/su /sbin/su 2>/dev/null",
            2500
        ).split("\n").filter { it.isNotBlank() }

        val evidence = found.map { "路径存在: $it" } +
            which.map { "shell: $it" } +
            listOf("已扫描 ${KnownLists.SU_PATHS.size} 个已知路径")

        return if (found.isNotEmpty()) {
            Outcome(Status.DANGER, "发现 ${found.size} 个 su 相关文件", evidence)
        } else if (which.isNotEmpty()) {
            Outcome(Status.WARN, "PATH 或目录列表中存在 su 痕迹，但未确认可用", evidence)
        } else {
            Outcome(Status.PASS, "未在常见路径发现 su", evidence)
        }
    }

    /** 2. 真正尝试执行 su */
    fun suExec(): Outcome {
        val attempts = listOf("su -c id", "su 0 id", "su --version", "su -v", "su -h")
        val evidence = mutableListOf<String>()
        var rooted = false
        var anyOutput = false

        for (cmd in attempts) {
            val r = Shell.exec(cmd, 2000)
            val out = r.out.trim()
            if (out.isNotEmpty()) anyOutput = true
            if (out.contains("uid=0")) rooted = true
            if (out.isNotEmpty()) {
                evidence += "$cmd -> ${out.lines().first().take(160)}"
            }
        }

        val status = when {
            rooted -> Status.DANGER
            anyOutput -> Status.WARN
            else -> Status.PASS
        }
        val summary = when (status) {
            Status.DANGER -> "su 可用且已获得 uid=0（root shell 可执行）"
            Status.WARN -> "su 命令有响应，但未能确认 root 权限"
            else -> "su 不可用"
        }
        return Outcome(status, summary, evidence.ifEmpty { listOf("所有 su 尝试均无输出或命令不存在") })
    }

    /** 3. busybox / toybox */
    fun busybox(): Outcome {
        val paths = listOf(
            "/system/bin/busybox", "/system/xbin/busybox", "/sbin/busybox",
            "/data/local/busybox", "/system/bin/toybox", "/system/xbin/toybox"
        )
        val found = paths.filter { Fs.exists(it) }
        val which = Shell.out("command -v busybox 2>/dev/null", 1500).trim()
        val evidence = found.map { "路径存在: $it" } +
            (if (which.isNotEmpty()) listOf("shell: $which") else emptyList())

        return when {
            found.any { it.contains("busybox") } -> Outcome(
                Status.WARN,
                "存在 busybox（常见于已 root / 修改过的系统）",
                evidence + "提示：部分厂商 ROM 自带 toybox 属正常情况"
            )
            which.isNotEmpty() -> Outcome(Status.WARN, "PATH 中存在 busybox", evidence)
            else -> Outcome(Status.PASS, "未发现 busybox", evidence.ifEmpty { listOf("未发现") })
        }
    }

    /** 4. 当前进程 uid（root shell 启动的应用 uid 会是 0） */
    fun shellUid(): Outcome {
        val uid = Shell.out("id 2>/dev/null", 1500).trim()
        val uidNum = Regex("uid=(\\d+)").find(uid)?.groupValues?.get(1)
        val evidence = listOf("id -> ${uid.ifEmpty { "无输出" }}")
        return if (uidNum == "0") {
            Outcome(Status.DANGER, "当前进程以 uid=0 运行", evidence)
        } else {
            Outcome(Status.PASS, "当前进程 uid=$uidNum（普通应用权限）", evidence)
        }
    }

    /** 5. 系统目录是否可写 */
    fun writableSystem(): Outcome {
        val dirs = listOf("/system", "/system/bin", "/system/app", "/system/xbin", "/vendor", "/etc", "/sbin")
        val writable = dirs.filter { Fs.isWritable(it) }
        val evidence = dirs.map { "$it -> ${if (Fs.isWritable(it)) "可写" else "不可写"}" }
        return if (writable.isNotEmpty()) {
            Outcome(Status.DANGER, "${writable.size} 个系统目录可写（正常应为只读）", evidence)
        } else {
            Outcome(Status.PASS, "系统目录均不可写", evidence)
        }
    }

    /** 6. root 相关系统属性 */
    fun rootProps(): Outcome {
        val checks = listOf(
            "ro.secure" to listOf("0"),
            "ro.debuggable" to listOf("1"),
            "service.adb.root" to listOf("1"),
            "persist.sys.root_access" to listOf("1", "2", "3"),
            "ro.build.type" to listOf("userdebug", "eng"),
            "ro.build.tags" to listOf("test-keys"),
            "ro.build.selinux" to listOf("0")
        )
        val evidence = mutableListOf<String>()
        var danger = false
        var warn = false
        for ((key, bad) in checks) {
            val v = Props.get(key)
            if (v.isEmpty()) {
                evidence += "$key = (未设置)"
                continue
            }
            val hit = bad.any { it.equals(v, ignoreCase = true) }
            if (hit) {
                danger = true
                evidence += "$key = $v  <== 异常"
            } else {
                if (key == "ro.build.type" && v != "user") warn = true
                evidence += "$key = $v"
            }
        }
        return Outcome(
            if (danger) Status.DANGER else if (warn) Status.WARN else Status.PASS,
            when {
                danger -> "存在 root / 调试版系统属性"
                warn -> "构建类型非 user"
                else -> "系统属性未见 root 迹象"
            },
            evidence
        )
    }

    /** 7. root 常用目录 */
    fun rootDirs(): Outcome {
        val dirs = listOf(
            "/data/local", "/data/local/bin", "/data/local/xbin", "/data/local/tmp",
            "/data/adb", "/data/su", "/su", "/sbin", "/system/xbin", "/system/etc/init.d"
        )
        val exist = mutableListOf<String>()
        val evidence = mutableListOf<String>()
        for (d in dirs) {
            val e = Fs.exists(d)
            if (e) exist += d
            val children = if (Fs.isDir(d)) Fs.list(d).size else -1
            evidence += "$d -> ${if (e) "存在" else "不存在"}${if (children >= 0) "（可列出 $children 项）" else ""}"
        }
        val risky = exist.filter { it != "/data/local/tmp" && it != "/sbin" }
        return when {
            Fs.isNonEmptyDir("/data/adb") -> Outcome(
                Status.DANGER,
                "/data/adb 存在且有内容（Magisk / KernelSU 的专用目录）",
                evidence + Fs.list("/data/adb").map { "  /data/adb/$it" }
            )
            risky.size >= 2 -> Outcome(Status.WARN, "存在 ${risky.size} 个典型 root 目录", evidence)
            else -> Outcome(Status.PASS, "未发现典型 root 目录", evidence)
        }
    }

    /** 8. init.d 启动脚本 */
    fun initD(): Outcome {
        val dir = "/system/etc/init.d"
        val files = Fs.list(dir)
        val se = Fs.exists("/system/etc/install-recovery.sh")
        val evidence = mutableListOf<String>()
        evidence += "$dir -> ${if (Fs.exists(dir)) "存在" else "不存在"}"
        if (files.isNotEmpty()) evidence += files.map { "  $it" }.joinToString("\n")
        evidence += "/system/etc/install-recovery.sh -> ${if (se) "存在" else "不存在"}"
        return when {
            files.isNotEmpty() -> Outcome(Status.WARN, "存在 ${files.size} 个 init.d 启动脚本", evidence)
            se -> Outcome(Status.WARN, "存在 install-recovery.sh（常被 root 方案利用）", evidence)
            else -> Outcome(Status.PASS, "无 init.d 脚本", evidence)
        }
    }
}
