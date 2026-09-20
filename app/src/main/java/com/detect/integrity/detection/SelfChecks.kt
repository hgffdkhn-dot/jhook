package com.detect.integrity.detection

import android.content.Context
import android.content.pm.ApplicationInfo
import com.detect.integrity.BuildConfig
import com.detect.integrity.model.Outcome
import com.detect.integrity.model.Status
import com.detect.integrity.util.Hash
import com.detect.integrity.util.Pkg
import com.detect.integrity.util.Shell

/**
 * 应用自身完整性：签名指纹、安装来源、可调试标志、APK 路径
 */
object SelfChecks {

    /** 1. 自身签名指纹与期望值比对 */
    fun signature(context: Context, expected: String): Outcome {
        val pkg = context.packageName
        val shas = Pkg.signatureSha256(context, pkg)
        val certs = Pkg.certificates(context, pkg)
        val evidence = mutableListOf<String>()
        evidence += "包名: $pkg"
        shas.forEachIndexed { i, s -> evidence += "签名 #$i SHA-256: $s" }
        certs.forEach { c ->
            evidence += "subject: ${c.subjectDN}"
            evidence += "issuer: ${c.issuerDN}"
            evidence += "有效期: ${c.notBefore} ~ ${c.notAfter}"
        }
        val want = Hash.normalize(expected.ifBlank { BuildConfig.EXPECTED_SIGNATURE_SHA256 })
        return when {
            shas.isEmpty() -> Outcome(Status.ERROR, "读取自身签名失败", evidence)
            want.isBlank() -> Outcome(
                Status.INFO,
                "未配置期望签名，当前指纹: ${shas.first().take(16)}…（可在设置中填入以防二次打包）",
                evidence
            )
            shas.any { Hash.normalize(it) == want } -> Outcome(Status.PASS, "签名指纹与期望值一致", evidence)
            else -> Outcome(Status.DANGER, "签名与期望值不一致（可能被二次打包）", evidence + "期望值: $want")
        }
    }

    /** 2. 安装来源 */
    fun installer(context: Context): Outcome {
        val pkg = context.packageName
        val installer = Pkg.installerOf(context, pkg)
        val evidence = listOf(
            "安装来源: ${installer.ifEmpty { "(未知/ADB/手动安装)" }}",
            "包名: $pkg"
        )
        return when {
            installer == "com.android.vending" -> Outcome(Status.PASS, "来自 Google Play 商店", evidence)
            installer.isEmpty() -> Outcome(Status.WARN, "非商店安装（可能是 ADB / 手动安装）", evidence)
            else -> Outcome(Status.WARN, "安装来源: $installer", evidence)
        }
    }

    /** 3. 可调试标志 */
    fun debuggable(context: Context): Outcome {
        val flags = context.applicationInfo.flags
        val debuggable = (flags and ApplicationInfo.FLAG_DEBUGGABLE) != 0
        val evidence = listOf(
            "ApplicationInfo.FLAG_DEBUGGABLE = $debuggable",
            "BuildConfig.DEBUG = ${BuildConfig.DEBUG}",
            "flags = 0x${Integer.toHexString(flags)}"
        )
        return if (debuggable) {
            Outcome(Status.WARN, "应用被标记为可调试（debug 构建）", evidence)
        } else {
            Outcome(Status.PASS, "非可调试构建", evidence)
        }
    }

    /** 4. APK / so 路径 */
    fun apkPath(context: Context): Outcome {
        val ai = context.applicationInfo
        val src = ai.sourceDir ?: ""
        val nativeDir = ai.nativeLibraryDir ?: ""
        val evidence = listOf(
            "sourceDir: $src",
            "publicSourceDir: ${ai.publicSourceDir}",
            "nativeLibraryDir: $nativeDir",
            "dataDir: ${ai.dataDir ?: ""}"
        )
        val inSystem = src.startsWith("/system") || src.startsWith("/product") || src.startsWith("/apex")
        val inDataApp = src.startsWith("/data/app")
        val ok = inSystem || inDataApp
        return when {
            !ok -> Outcome(Status.WARN, "APK 路径异常: $src", evidence)
            inSystem -> Outcome(Status.PASS, "以系统应用方式安装", evidence)
            else -> Outcome(Status.PASS, "APK 位于 /data/app", evidence)
        }
    }

    /** 5. 自身进程 / 数据目录被改写的痕迹 */
    fun dataDir(context: Context): Outcome {
        val dirs = listOf(context.filesDir?.parent ?: "", context.codeCacheDir?.absolutePath ?: "")
        val out = Shell.out("ls -la ${context.filesDir?.parent ?: "/data/data/unknown"} 2>/dev/null", 2000)
        val evidence = dirs.map { "目录: $it" } + out.lines().take(20)
        return Outcome(Status.INFO, "应用私有目录已列出（${
            dirs.first().ifEmpty { "未知" }
        }）", evidence)
    }
}
