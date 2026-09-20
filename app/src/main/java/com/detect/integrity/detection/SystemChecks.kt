package com.detect.integrity.detection

import android.os.Build
import android.provider.Settings
import android.content.Context
import com.detect.integrity.model.KnownLists
import com.detect.integrity.model.Outcome
import com.detect.integrity.model.Status
import com.detect.integrity.util.Fs
import com.detect.integrity.util.Hash
import com.detect.integrity.util.Pkg
import com.detect.integrity.util.Props
import com.detect.integrity.util.Shell
import java.io.ByteArrayInputStream
import java.security.cert.CertificateFactory
import java.security.cert.X509Certificate
import java.util.zip.ZipFile

/**
 * 系统完整性检测：Verified Boot、vbmeta、dm-verity、SELinux、构建指纹、系统文件等
 */
object SystemChecks {

    /** 1. Verified Boot 状态 */
    fun verifiedBoot(): Outcome {
        val state = Props.getOrBoot("verifiedbootstate").lowercase()
        val also = Props.get("ro.boot.verifiedbootstate")
        val evidence = listOf(
            "ro.boot.verifiedbootstate = ${also.ifEmpty { "(无)" }}",
            "/proc/cmdline androidboot.verifiedbootstate = ${state.ifEmpty { "(无)" }}",
            "ro.boot.verifiedbooterror = ${Props.get("ro.boot.verifiedbooterror")}"
        )
        return when {
            state == "green" || also.equals("green", true) -> Outcome(Status.PASS, "Verified Boot: GREEN（校验通过）", evidence)
            state == "orange" || also.equals("orange", true) -> Outcome(Status.DANGER, "Verified Boot: ORANGE（bootloader 已解锁）", evidence)
            state == "yellow" || also.equals("yellow", true) -> Outcome(Status.WARN, "Verified Boot: YELLOW（使用自定义密钥）", evidence)
            state == "red" || also.equals("red", true) -> Outcome(Status.DANGER, "Verified Boot: RED（校验失败）", evidence)
            else -> Outcome(Status.INFO, "无法读取 verified boot 状态", evidence)
        }
    }

    /** 2. vbmeta 设备状态 */
    fun vbmetaState(): Outcome {
        val state = Props.get("ro.boot.vbmeta.device_state").lowercase()
        val evidence = listOf(
            "ro.boot.vbmeta.device_state = ${state.ifEmpty { "(无)" }}",
            "ro.boot.vbmeta.avb_version = ${Props.get("ro.boot.vbmeta.avb_version")}",
            "ro.boot.vbmeta.hash_alg = ${Props.get("ro.boot.vbmeta.hash_alg")}"
        )
        return when {
            state == "locked" -> Outcome(Status.PASS, "vbmeta: locked", evidence)
            state == "unlocked" -> Outcome(Status.DANGER, "vbmeta: unlocked（镜像可被随意替换）", evidence)
            else -> Outcome(Status.INFO, "无法读取 vbmeta 状态", evidence)
        }
    }

    /** 3. bootloader 解锁 */
    fun flashLocked(): Outcome {
        val locked = Props.get("ro.boot.flash.locked")
        val bl = Props.get("ro.bootloader", Build.BOOTLOADER)
        val unlockedProp = Props.get("ro.boot.unlocked")
        val evidence = listOf(
            "ro.boot.flash.locked = ${locked.ifEmpty { "(无)" }}",
            "ro.bootloader = $bl",
            "ro.boot.unlocked = ${unlockedProp.ifEmpty { "(无)" }}",
            "sys.oem_unlock_allowed = ${Props.get("sys.oem_unlock_allowed")}"
        )
        return when {
            locked == "0" -> Outcome(Status.DANGER, "bootloader 处于解锁状态", evidence)
            unlockedProp == "1" -> Outcome(Status.DANGER, "系统标记为已解锁", evidence)
            locked == "1" -> Outcome(Status.PASS, "bootloader 已锁定", evidence)
            else -> Outcome(Status.INFO, "无法确认 bootloader 锁定状态", evidence)
        }
    }

    /** 4. dm-verity */
    fun dmVerity(): Outcome {
        val mode = Props.get("ro.boot.veritymode")
        val verity = Props.get("ro.boot.verity")
        val partitions = Props.get("ro.boot.verity.marked-mount-point")
        val evidence = listOf(
            "ro.boot.veritymode = ${mode.ifEmpty { "(无)" }}",
            "ro.boot.verity = ${verity.ifEmpty { "(无)" }}",
            "marked-mount-point = ${partitions.ifEmpty { "(无)" }}",
            "getprop partition.system.verified = ${Props.get("partition.system.verified")}"
        )
        return when {
            mode.equals("enforcing", true) -> Outcome(Status.PASS, "dm-verity: enforcing", evidence)
            mode.equals("eio", true) -> Outcome(Status.WARN, "dm-verity: eio（出错仅返回 I/O 错误）", evidence)
            mode.equals("disabled", true) -> Outcome(Status.DANGER, "dm-verity 已被禁用", evidence)
            else -> Outcome(Status.INFO, "无法读取 dm-verity 模式", evidence)
        }
    }

    /** 5. SELinux 状态 */
    fun selinux(): Outcome {
        val enforceFile = Fs.readText("/sys/fs/selinux/enforce").trim()
        val getenforce = Shell.out("getenforce 2>/dev/null", 1500).trim()
        val fsExists = Fs.exists("/sys/fs/selinux")
        val evidence = listOf(
            "/sys/fs/selinux = ${if (fsExists) "存在" else "不存在"}",
            "/sys/fs/selinux/enforce = ${enforceFile.ifEmpty { "(无)" }}",
            "getenforce = ${getenforce.ifEmpty { "(无)" }}",
            "ro.build.selinux = ${Props.get("ro.build.selinux")}"
        )
        val permissive = enforceFile == "0" || getenforce.equals("Permissive", true)
        return when {
            !fsExists && getenforce.isEmpty() -> Outcome(Status.INFO, "无法读取 SELinux 状态", evidence)
            permissive -> Outcome(Status.DANGER, "SELinux 处于 Permissive（宽松）模式", evidence)
            else -> Outcome(Status.PASS, "SELinux: Enforcing", evidence)
        }
    }

    /** 6. build tags（release-keys / test-keys） */
    fun buildTags(): Outcome {
        val tags = Props.get("ro.build.tags", Build.TAGS ?: "")
        val fingerprint = "${Build.FINGERPRINT}"
        val evidence = listOf(
            "ro.build.tags = $tags",
            "Build.TAGS = ${Build.TAGS}",
            "ro.build.fingerprint = $fingerprint",
            "ro.build.description = ${Props.get("ro.build.description", Build.DISPLAY)}"
        )
        return when {
            tags.contains("test-keys") -> Outcome(Status.DANGER, "系统使用 test-keys 签名（非官方发布密钥）", evidence)
            tags.contains("dev-keys") -> Outcome(Status.WARN, "系统使用 dev-keys 签名", evidence)
            tags.contains("release-keys") -> Outcome(Status.PASS, "release-keys 官方签名", evidence)
            else -> Outcome(Status.INFO, "构建标签: $tags", evidence)
        }
    }

    /** 7. 构建类型 */
    fun buildType(): Outcome {
        val type = Props.get("ro.build.type", Build.TYPE)
        val debuggable = Props.get("ro.debuggable")
        val secure = Props.get("ro.secure")
        val evidence = listOf(
            "ro.build.type = $type",
            "Build.TYPE = ${Build.TYPE}",
            "ro.debuggable = $debuggable",
            "ro.secure = $secure"
        )
        return when (type) {
            "user" -> Outcome(Status.PASS, "user 版系统", evidence)
            "userdebug" -> Outcome(Status.WARN, "userdebug 版系统（带调试能力）", evidence)
            "eng" -> Outcome(Status.DANGER, "eng 工程版系统", evidence)
            else -> Outcome(Status.INFO, "构建类型: $type", evidence)
        }
    }

    /** 8. OTA 公钥证书 */
    fun otaCerts(): Outcome {
        val path = "/system/etc/security/otacerts.zip"
        val evidence = mutableListOf<String>()
        if (!Fs.exists(path)) {
            return Outcome(Status.WARN, "未找到 otacerts.zip（部分设备路径不同）", listOf("$path 不存在"))
        }
        return try {
            ZipFile(path).use { zip ->
                for (entry in zip.entries()) {
                    if (entry.isDirectory) continue
                    val cert = CertificateFactory.getInstance("X509")
                        .generateCertificate(ByteArrayInputStream(zip.getInputStream(entry).readBytes())) as X509Certificate
                    evidence += "subject: ${cert.subjectDN}"
                    evidence += "issuer: ${cert.issuerDN}"
                    evidence += "serial: ${cert.serialNumber}"
                    evidence += "有效期: ${cert.notBefore} ~ ${cert.notAfter}"
                    evidence += "SHA-256: ${Hash.sha256(cert.publicKey.encoded)}"
                    val s = cert.subjectDN.name.lowercase()
                    if (s.contains("test") || s.contains("aosp")) {
                        return Outcome(Status.WARN, "OTA 证书疑似 testkey/AOSP 调试密钥", evidence)
                    }
                }
                Outcome(Status.PASS, "OTA 证书: ${evidence.firstOrNull() ?: "已读取"}".take(120), evidence)
            }
        } catch (e: Exception) {
            Outcome(Status.INFO, "otacerts.zip 无法解析: ${e.message}", evidence)
        }
    }

    /** 9. 系统框架（android 包）签名证书 */
    fun platformSignature(context: Context): Outcome {
        val certs = Pkg.certificates(context, "android")
        if (certs.isEmpty()) {
            return Outcome(Status.INFO, "无法读取系统框架签名", listOf("getPackageInfo(\"android\") 失败"))
        }
        val evidence = mutableListOf<String>()
        certs.forEach { c ->
            evidence += "subject: ${c.subjectDN}"
            evidence += "issuer: ${c.issuerDN}"
            evidence += "SHA-256(公钥): ${Hash.sha256(c.publicKey.encoded)}"
            evidence += "有效期: ${c.notBefore} ~ ${c.notAfter}"
        }
        val tags = Props.get("ro.build.tags", Build.TAGS ?: "")
        return if (tags.contains("test-keys")) {
            Outcome(Status.DANGER, "系统签名疑似 test-keys", evidence)
        } else {
            Outcome(Status.PASS, "系统框架签名已读取（release 构建）", evidence)
        }
    }

    /** 10. OEM 解锁开关 */
    fun oemUnlock(context: Context): Outcome {
        val v = runCatching {
            Settings.Global.getInt(context.contentResolver, Settings.Global.OEM_UNLOCK_ALLOWED)
        }.getOrDefault(-1)
        val dev = runCatching {
            Settings.Global.getInt(context.contentResolver, Settings.Global.DEVELOPMENT_SETTINGS_ENABLED)
        }.getOrDefault(-1)
        val evidence = listOf(
            "oem_unlock_allowed = $v（0=禁止 1=允许 -1=不支持/未读）",
            "development_settings_enabled = $dev"
        )
        return when (v) {
            1 -> Outcome(Status.WARN, "OEM 解锁开关已打开", evidence)
            0 -> Outcome(Status.PASS, "OEM 解锁未开启", evidence)
            else -> Outcome(Status.INFO, "无法读取 OEM 解锁状态", evidence)
        }
    }

    /** 11. 回滚保护 */
    fun rollback(): Outcome {
        val idx = Props.get("ro.boot.rollback_index")
        val slot = Props.get("ro.boot.slot_suffix", Build.VERSION.SDK_INT.let { "" })
        val vbmetaDigest = Props.get("ro.boot.vbmeta.digest")
        val evidence = listOf(
            "ro.boot.rollback_index = ${idx.ifEmpty { "(无)" }}",
            "ro.boot.slot_suffix = ${slot.ifEmpty { "(无)" }}",
            "ro.boot.vbmeta.digest = ${vbmetaDigest.ifEmpty { "(无)" }}",
            "ro.boot.selinux = ${Props.get("ro.boot.selinux")}"
        )
        return Outcome(Status.INFO, "回滚索引: ${idx.ifEmpty { "未提供" }}", evidence)
    }

    /** 12. 安全补丁与版本信息 */
    fun versionInfo(): Outcome {
        val patch = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.M) Build.VERSION.SECURITY_PATCH else ""
        val evidence = listOf(
            "Android ${Build.VERSION.RELEASE} (API ${Build.VERSION.SDK_INT})",
            "安全补丁: ${patch.ifEmpty { "未提供" }}",
            "Build ID: ${Build.ID}",
            "设备: ${Build.MANUFACTURER} ${Build.MODEL} (${Build.DEVICE})",
            "主板: ${Build.BOARD} / 硬件: ${Build.HARDWARE}",
            "内核: ${System.getProperty("os.version")}",
            "ABI: ${Build.SUPPORTED_ABIS.joinToString()}"
        )
        val old = Build.VERSION.SDK_INT < Build.VERSION_CODES.O
        return Outcome(
            if (old) Status.WARN else Status.INFO,
            "Android ${Build.VERSION.RELEASE}，补丁 ${patch.ifEmpty { "未知" }}",
            evidence
        )
    }

    /** 13. 系统目录可疑文件扫描（耗时） */
    suspend fun fileScan(): Outcome = kotlinx.coroutines.withContext(kotlinx.coroutines.Dispatchers.IO) {
        val dirs = listOf("/system/bin", "/system/xbin", "/system/sbin", "/sbin", "/system/app", "/system/priv-app", "/data/local/tmp", "/data/local/bin")
        val hits = LinkedHashMap<String, List<String>>()
        for (d in dirs) {
            val found = Fs.findNames(d, KnownLists.SUSPICIOUS_FILE_KEYWORDS)
            if (found.isNotEmpty()) hits[d] = found
        }
        val evidence = mutableListOf<String>()
        hits.forEach { (d, files) ->
            evidence += "$d:"
            files.take(20).forEach { evidence += "  $it" }
        }
        val total = hits.values.sumOf { it.size }
        val hard = hits.entries.filter { (d, files) ->
            files.any { f ->
                val n = f.substringAfterLast('/').lowercase()
                n == "su" || n.startsWith("magisk") || n.contains("daemonsu") || n.contains("frida") || n.contains("xposed")
            }
        }
        if (evidence.isEmpty()) evidence += "未在任何系统目录中发现可疑文件名（已扫描 ${dirs.size} 个目录）"
        return@withContext when {
            hard.isNotEmpty() -> Outcome(Status.DANGER, "系统目录中发现 ${total} 个可疑文件（含明确 root 特征）", evidence)
            total > 0 -> Outcome(Status.WARN, "发现 $total 个可疑文件名", evidence)
            else -> Outcome(Status.PASS, "系统目录文件名扫描无异常", evidence)
        }
    }

    /** 14. 启动链路 / 分区哈希类属性 */
    fun bootChain(): Outcome {
        val keys = listOf(
            "ro.boot.bootloader", "ro.boot.hardware", "ro.boot.image",
            "ro.boot.bootreason", "ro.boot.revision", "ro.boot.serialno",
            "ro.boot.vbmeta.size", "ro.boot.dynamic_partitions",
            "ro.product.first_api_level", "ro.vendor.build.security_patch"
        )
        val evidence = keys.map { "$it = ${Props.get(it).ifEmpty { "(无)" }}" }
        val firstApi = Props.get("ro.product.first_api_level").toIntOrNull()
        val suspicious = firstApi != null && Build.VERSION.SDK_INT - firstApi >= 7
        return Outcome(
            if (suspicious) Status.INFO else Status.INFO,
            "首发 API $firstApi / 当前 API ${Build.VERSION.SDK_INT}",
            evidence
        )
    }
}
