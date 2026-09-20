package com.detect.integrity.util

import android.content.Context
import android.content.pm.PackageManager
import android.os.Build
import java.io.ByteArrayInputStream
import java.security.cert.CertificateFactory
import java.security.cert.X509Certificate

/**
 * 包管理相关：安装检测、签名指纹、证书信息。
 */
object Pkg {

    fun isInstalled(context: Context, pkg: String): Boolean = try {
        context.packageManager.getPackageInfo(pkg, 0)
        true
    } catch (_: Exception) {
        false
    }

    fun installedNames(context: Context): List<String> = try {
        @Suppress("DEPRECATION")
        context.packageManager.getInstalledPackages(0).map { it.packageName }
    } catch (e: Exception) {
        emptyList()
    }

    /** 已安装包中名字包含关键字的（受 Android 11+ 包可见性限制，可能不完整） */
    fun installedMatching(context: Context, keywords: List<String>): List<String> {
        val names = installedNames(context)
        if (names.isEmpty()) return emptyList()
        val lower = keywords.map { it.lowercase() }
        return names.filter { n ->
            val s = n.lowercase()
            lower.any { s.contains(it) }
        }.distinct().sorted()
    }

    /** 在给定的已知包名列表里，哪些装了 */
    fun installedFrom(context: Context, candidates: Collection<String>): List<String> =
        candidates.filter { isInstalled(context, it) }.distinct()

    private fun signatures(context: Context, pkg: String): Array<android.content.pm.Signature> {
        val pm = context.packageManager
        return try {
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
                val pi = pm.getPackageInfo(pkg, PackageManager.GET_SIGNING_CERTIFICATES)
                val si = pi.signingInfo
                val a = si?.apkContentsSigners
                if (!a.isNullOrEmpty()) a else si?.signingCertificateHistory ?: emptyArray()
            } else {
                @Suppress("DEPRECATION")
                pm.getPackageInfo(pkg, PackageManager.GET_SIGNATURES).signatures ?: emptyArray()
            }
        } catch (_: Exception) {
            emptyArray()
        }
    }

    fun signatureSha256(context: Context, pkg: String): List<String> =
        signatures(context, pkg).map { Hash.sha256(it.toByteArray()) }

    fun certificates(context: Context, pkg: String): List<X509Certificate> =
        signatures(context, pkg).mapNotNull { sig ->
            try {
                CertificateFactory.getInstance("X509")
                    .generateCertificate(ByteArrayInputStream(sig.toByteArray())) as? X509Certificate
            } catch (_: Exception) {
                null
            }
        }

    fun isSystemApp(context: Context, pkg: String): Boolean = try {
        val ai = context.packageManager.getApplicationInfo(pkg, 0)
        (ai.flags and android.content.pm.ApplicationInfo.FLAG_SYSTEM) != 0
    } catch (_: Exception) {
        false
    }

    fun installerOf(context: Context, pkg: String): String = try {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) {
            context.packageManager.getInstallSourceInfo(pkg).installingPackageName ?: ""
        } else {
            @Suppress("DEPRECATION")
            context.packageManager.getInstallerPackageName(pkg) ?: ""
        }
    } catch (_: Exception) {
        ""
    }

    fun versionName(context: Context, pkg: String): String = try {
        context.packageManager.getPackageInfo(pkg, 0).versionName ?: ""
    } catch (_: Exception) {
        ""
    }
}
