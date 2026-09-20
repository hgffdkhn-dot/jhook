package com.detect.integrity.detection

import com.detect.integrity.model.KnownLists
import com.detect.integrity.model.Outcome
import com.detect.integrity.model.Status
import com.detect.integrity.util.Proc

/**
 * 系统挂载相关检测
 */
object MountChecks {

    private val READ_ONLY_PARTITIONS = listOf(
        "/system", "/system_ext", "/vendor", "/product", "/odm", "/oem", "/apex"
    )

    /** 1. 只读分区是否被 rw 挂载 */
    fun systemRw(): Outcome {
        val mounts = Proc.mounts()
        val evidence = mutableListOf<String>()
        val bad = mutableListOf<String>()
        for (p in READ_ONLY_PARTITIONS) {
            val m = mounts.filter { it.target == p }
            if (m.isEmpty()) continue
            for (entry in m) {
                evidence += "${entry.target} [${entry.fs}] ${if (entry.isRw) "rw" else "ro"} <- ${entry.source}"
                if (entry.isRw) bad += entry.target
            }
        }
        if (evidence.isEmpty()) evidence += "未匹配到只读分区挂载记录"
        return if (bad.isNotEmpty()) {
            Outcome(Status.DANGER, "${bad.size} 个只读分区被以可写方式挂载", evidence)
        } else {
            Outcome(Status.PASS, "系统分区均以只读方式挂载", evidence)
        }
    }

    /** 2. tmpfs / overlay 覆盖 */
    fun tmpfsOverlay(): Outcome {
        val mounts = Proc.mounts()
        val targets = KnownLists.SYSTEM_MOUNT_POINTS
        val hit = mounts.filter { m ->
            (m.fs.equals("tmpfs", true) || m.fs.equals("overlay", true)) &&
                targets.any { t -> m.target == t || m.target.startsWith("$t/") }
        }
        val evidence = hit.map { m -> "${m.target} [${m.fs}] <- ${m.source} opts=${m.options.joinToString(",")}" }
            .ifEmpty { listOf("未发现 tmpfs / overlay 覆盖系统分区") }
        val critical = hit.filter { it.target.startsWith("/system") || it.target.startsWith("/vendor") || it.target == "/" }
        return when {
            critical.isNotEmpty() -> Outcome(Status.DANGER, "${critical.size} 个系统分区被 tmpfs/overlay 覆盖", evidence)
            hit.isNotEmpty() -> Outcome(Status.WARN, "发现 ${hit.size} 处 tmpfs/overlay 挂载", evidence)
            else -> Outcome(Status.PASS, "无 tmpfs / overlay 覆盖", evidence)
        }
    }

    /** 3. 可疑挂载点（root 方案常用） */
    fun suspicious(): Outcome {
        val mounts = Proc.mounts()
        val keywords = listOf("magisk", "zygisk", "sbin", "su", "supersu", "xbin", "core", "mirror", "ksu", "apatch")
        val hit = mounts.filter { m ->
            val s = (m.source + " " + m.target).lowercase()
            keywords.any { s.contains(it) }
        }
        val evidence = hit.map { it.raw.take(180) }
            .ifEmpty { listOf("挂载点中未发现 root 方案常用关键字") }
        val strong = hit.filter { m ->
            val s = (m.source + m.target).lowercase()
            s.contains("magisk") || s.contains("zygisk") || s.contains("mirror") || s.contains("supersu")
        }
        return when {
            strong.isNotEmpty() -> Outcome(Status.DANGER, "发现 ${strong.size} 条明确 root 特征挂载", evidence)
            hit.isNotEmpty() -> Outcome(Status.WARN, "发现 ${hit.size} 条可疑挂载", evidence)
            else -> Outcome(Status.PASS, "挂载点无异常", evidence)
        }
    }

    /** 4. loop 设备挂载（systemless img） */
    fun loopDevices(): Outcome {
        val mounts = Proc.mounts()
        val hit = mounts.filter { m -> m.source.startsWith("/dev/block/loop") }
        val evidence = hit.map { "${m.target} <- ${m.source} [${m.fs}]" }
            .ifEmpty { listOf("无 loop 设备挂载") }
        return if (hit.isNotEmpty()) {
            Outcome(Status.WARN, "发现 ${hit.size} 个 loop 设备挂载（常见于模块镜像）", evidence)
        } else {
            Outcome(Status.PASS, "无 loop 设备挂载", evidence)
        }
    }

    /** 5. dm-verity / verity 挂载选项 */
    fun verity(): Outcome {
        val mounts = Proc.mounts()
        val withVerity = mounts.filter { m -> m.hasOption("verity") || m.hasOption("dm-verity") }
        val sysRo = mounts.filter { m ->
            (m.target == "/system" || m.target == "/vendor") && !m.isRw
        }
        val evidence = mutableListOf<String>()
        evidence += "启用 verity 的挂载: ${withVerity.size}"
        withVerity.take(8).forEach { evidence += "  ${it.target} [${it.fs}] ${it.options.joinToString(",")}" }
        evidence += "只读系统分区: ${sysRo.size}"
        val status = if (withVerity.isNotEmpty()) Status.PASS else Status.WARN
        return Outcome(
            status,
            if (withVerity.isNotEmpty()) "分区启用了 dm-verity 校验" else "未发现 verity 挂载选项，需结合 vbmeta 状态判断",
            evidence
        )
    }

    /** 6. 完整挂载表（信息） */
    fun fullTable(): Outcome {
        val mounts = Proc.mounts()
        val evidence = mounts.map { m ->
            "${m.target} [${m.fs}] <- ${m.source} (${m.options.joinToString(",")})"
        }
        return Outcome(Status.INFO, "共 ${mounts.size} 条挂载记录", evidence)
    }
}
