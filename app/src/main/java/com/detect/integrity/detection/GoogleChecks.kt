package com.detect.integrity.detection

import android.content.Context
import com.detect.integrity.model.KnownLists
import com.detect.integrity.model.Outcome
import com.detect.integrity.model.Status
import com.detect.integrity.util.Fs
import com.detect.integrity.util.Hash
import com.detect.integrity.util.Pkg
import com.google.android.gms.common.ConnectionResult
import com.google.android.gms.common.GoogleApiAvailability
import java.io.ByteArrayInputStream
import java.security.KeyStore
import java.security.cert.CertificateFactory
import java.security.cert.X509Certificate
import java.util.zip.ZipFile

/**
 * 谷歌证书相关检测：
 * 1) 系统信任库中的 Google 根证书
 * 2) Google Play 服务 / 应用商店的签名证书
 * 3) 系统证书目录完整性
 */
object GoogleChecks {

    /** 1. Google Play 服务可用性 */
    fun availability(context: Context): Outcome {
        return try {
            val api = GoogleApiAvailability.getInstance()
            val code = api.isGooglePlayServicesAvailable(context)
            val name = try {
                api.getErrorString(code)
            } catch (_: Exception) {
                ""
            }
            val ver = Pkg.versionName(context, "com.google.android.gms")
            val evidence = listOf(
                "isGooglePlayServicesAvailable = $code ($name)",
                "GMS 版本: ${ver.ifEmpty { "未安装" }}",
                "是否可更新: ${runCatching { api.isUserResolvableError(code) }.getOrDefault(false)}"
            )
            when (code) {
                ConnectionResult.SUCCESS -> Outcome(Status.PASS, "Google Play 服务可用（$ver）", evidence)
                ConnectionResult.SERVICE_MISSING,
                ConnectionResult.SERVICE_DISABLED,
                ConnectionResult.SERVICE_INVALID -> Outcome(Status.WARN, "Google Play 服务不可用/被裁剪", evidence)
                else -> Outcome(Status.WARN, "Google Play 服务状态异常 ($code)", evidence)
            }
        } catch (e: Exception) {
            Outcome(Status.ERROR, "GMS 检测失败: ${e.message}", listOf(e.javaClass.simpleName))
        }
    }

    /** 2. GMS 签名证书校验 */
    fun gmsSignature(context: Context): Outcome = checkGooglePackage(context, "com.google.android.gms", "Google Play 服务")

    /** 3. 应用商店签名证书校验 */
    fun vendingSignature(context: Context): Outcome = checkGooglePackage(context, "com.android.vending", "Google Play 商店")

    private fun checkGooglePackage(context: Context, pkg: String, label: String): Outcome {
        if (!Pkg.isInstalled(context, pkg)) {
            return Outcome(Status.INFO, "$label 未安装", listOf("$pkg 不存在（国行/无 GMS 设备常见）"))
        }
        val certs = Pkg.certificates(context, pkg)
        val shas = Pkg.signatureSha256(context, pkg)
        if (certs.isEmpty()) {
            return Outcome(Status.INFO, "无法读取 $label 签名", listOf("$pkg 签名读取失败"))
        }
        val evidence = mutableListOf<String>()
        certs.forEachIndexed { i, c ->
            evidence += "证书 #$i subject: ${c.subjectDN}"
            evidence += "证书 #$i issuer: ${c.issuerDN}"
            evidence += "证书 #$i 有效期: ${c.notBefore} ~ ${c.notAfter}"
            evidence += "证书 #$i SHA-256: ${shas.getOrElse(i) { "" }}"
        }
        evidence += "系统应用: ${Pkg.isSystemApp(context, pkg)}"
        evidence += "安装来源: ${Pkg.installerOf(context, pkg).ifEmpty { "(无)" }}"

        val subject = certs.first().subjectDN.name
        val isGoogleIssued = isGoogleDn(subject) && isGoogleDn(certs.first().issuerDN.name)
        val expired = certs.any { it.notAfter.time < System.currentTimeMillis() }
        return when {
            expired -> Outcome(Status.WARN, "$label 签名证书已过期", evidence)
            !isGoogleIssued -> Outcome(Status.DANGER, "$label 签名主体非 Google（可能被替换/伪造）", evidence)
            !Pkg.isSystemApp(context, pkg) -> Outcome(Status.WARN, "$label 非系统应用（侧载安装）", evidence)
            else -> Outcome(Status.PASS, "$label 签名校验通过", evidence)
        }
    }

    private fun isGoogleDn(dn: String): Boolean {
        val s = dn.lowercase()
        return s.contains("google") || s.contains("android") || s.contains("gts")
    }

    /** 4. 系统信任库中的 Google 根证书 */
    fun trustStore(): Outcome {
        val google = LinkedHashMap<String, String>()
        var total = 0
        try {
            val ks = KeyStore.getInstance("AndroidCAStore")
            ks.load(null)
            val aliases = ks.aliases()
            while (aliases.hasMoreElements()) {
                val alias = aliases.nextElement()
                val cert = ks.getCertificate(alias) as? X509Certificate ?: continue
                total++
                val dn = (cert.subjectDN.name + " | " + cert.issuerDN.name).lowercase()
                if (KnownLists.GOOGLE_CA_KEYWORDS.any { dn.contains(it) }) {
                    google[alias] = "${cert.subjectDN} | SHA-256=${Hash.sha256(cert.encoded)} | 有效期至 ${cert.notAfter}"
                }
            }
        } catch (e: Exception) {
            return Outcome(Status.ERROR, "读取系统信任库失败: ${e.message}", listOf(e.javaClass.simpleName))
        }
        val evidence = mutableListOf<String>()
        evidence += "系统信任库证书总数: $total"
        evidence += "Google 相关根证书: ${google.size}"
        google.entries.take(15).forEach { (k, v) -> evidence += "  $k -> $v" }
        return when {
            total == 0 -> Outcome(Status.WARN, "系统信任库为空", evidence)
            google.isEmpty() -> Outcome(Status.WARN, "信任库中未找到 Google 根证书（可能被裁剪）", evidence)
            else -> Outcome(Status.PASS, "信任库含 ${google.size} 张 Google 根证书", evidence)
        }
    }

    /** 5. 系统 CA 目录完整性 */
    fun caDirectory(): Outcome {
        val dir = "/system/etc/security/cacerts"
        val files = Fs.list(dir)
        val apex = Fs.list("/apex/com.android.conscrypt/cacerts")
        val evidence = mutableListOf<String>()
        evidence += "$dir -> ${files.size} 个文件${if (files.isEmpty()) "（不可列或已迁移到 APEX）" else ""}"
        if (apex.isNotEmpty()) evidence += "/apex/com.android.conscrypt/cacerts -> ${apex.size} 个文件"
        // 抽样读取并校验是否为合法 X509
        var valid = 0
        var broken = 0
        val sample = (files.ifEmpty { apex }).take(30)
        for (name in sample) {
            val path = (if (files.isNotEmpty()) "$dir/$name" else "/apex/com.android.conscrypt/cacerts/$name")
            val bytes = try {
                java.io.File(path).readBytes()
            } catch (_: Exception) {
                continue
            }
            val ok = try {
                CertificateFactory.getInstance("X509")
                    .generateCertificate(ByteArrayInputStream(bytes)) != null
            } catch (_: Exception) {
                false
            }
            if (ok) valid++ else broken++
        }
        evidence += "抽样 ${sample.size} 个证书文件：可解析 $valid，异常 $broken"
        return when {
            broken > 0 -> Outcome(Status.WARN, "存在 $broken 个无法解析的证书文件（可能被篡改）", evidence)
            valid > 0 -> Outcome(Status.PASS, "系统 CA 目录证书可正常解析", evidence)
            else -> Outcome(Status.INFO, "无法访问系统 CA 目录", evidence)
        }
    }

    /** 6. 系统证书压缩包（cacerts_google 等 APEX 内容） */
    fun apexConscrypt(): Outcome {
        val paths = listOf(
            "/apex/com.android.conscrypt/cacerts",
            "/system/etc/security/cacerts_google",
            "/apex/com.android.art",
            "/apex/com.android.runtime"
        )
        val evidence = paths.map { "$it -> ${if (Fs.exists(it)) "存在" else "不存在"}" }
        val missing = paths.count { !Fs.exists(it) }
        return if (missing >= 3) {
            Outcome(Status.WARN, "部分系统 APEX / 证书目录缺失", evidence)
        } else {
            Outcome(Status.PASS, "系统 APEX 与证书目录存在", evidence)
        }
    }

    /** 7. otacerts 与系统证书链一致性（复用 ZipFile 解析） */
    fun otaZip(): Outcome {
        val path = "/system/etc/security/otacerts.zip"
        if (!Fs.exists(path)) {
            return Outcome(Status.INFO, "无 otacerts.zip", listOf("$path 不存在"))
        }
        return try {
            ZipFile(path).use { zip ->
                val evidence = mutableListOf<String>()
                for (e in zip.entries()) {
                    if (e.isDirectory) continue
                    val cert = CertificateFactory.getInstance("X509")
                        .generateCertificate(ByteArrayInputStream(zip.getInputStream(e).readBytes())) as X509Certificate
                    evidence += "${e.name}: ${cert.subjectDN}"
                }
                Outcome(Status.INFO, "otacerts.zip 含 ${evidence.size} 张证书", evidence)
            }
        } catch (e: Exception) {
            Outcome(Status.INFO, "otacerts.zip 解析失败: ${e.message}", listOf(e.javaClass.simpleName))
        }
    }
}
