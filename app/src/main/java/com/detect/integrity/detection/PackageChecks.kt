package com.detect.integrity.detection

import android.content.Context
import android.provider.Settings
import com.detect.integrity.model.KnownLists
import com.detect.integrity.model.Outcome
import com.detect.integrity.model.Status
import com.detect.integrity.util.Pkg
import com.detect.integrity.util.Shell

/**
 * 风险应用检测
 */
object PackageChecks {

    /** 1. root 授权管理类应用 */
    fun rootManagers(context: Context): Outcome {
        val installed = Pkg.installedFrom(context, KnownLists.ROOT_PACKAGES)
        val evidence = installed.map { "已安装: $it (${Pkg.versionName(context, it)})" }
            .ifEmpty { listOf("未发现已知 root 授权管理类应用（已比对 ${KnownLists.ROOT_PACKAGES.size} 个包名）") }
        return if (installed.isNotEmpty()) {
            Outcome(Status.DANGER, "发现 ${installed.size} 个 root 相关应用", evidence)
        } else {
            Outcome(Status.PASS, "无 root 授权管理类应用", evidence)
        }
    }

    /** 2. Hook / 注入框架应用 */
    fun hookApps(context: Context): Outcome {
        val installed = Pkg.installedFrom(context, KnownLists.HOOK_PACKAGES)
        val evidence = installed.map { "已安装: $it (${Pkg.versionName(context, it)})" }
            .ifEmpty { listOf("未发现已知 Hook 框架应用（已比对 ${KnownLists.HOOK_PACKAGES.size} 个包名）") }
        return if (installed.isNotEmpty()) {
            Outcome(Status.DANGER, "发现 ${installed.size} 个 Hook / 注入类应用", evidence)
        } else {
            Outcome(Status.PASS, "无 Hook 框架应用", evidence)
        }
    }

    /** 3. 已安装应用包名关键字扫描 */
    fun keywordScan(context: Context): Outcome {
        val matched = Pkg.installedMatching(context, KnownLists.PACKAGE_KEYWORDS)
        val names = Pkg.installedNames(context)
        val evidence = mutableListOf<String>()
        evidence += "可见包数量: ${names.size}（Android 11+ 受包可见性限制，可能不完整）"
        evidence += matched.ifEmpty { listOf("未命中任何关键字") }
        return if (matched.isNotEmpty()) {
            Outcome(Status.WARN, "发现 ${matched.size} 个包名含风险关键字的应用", evidence)
        } else {
            Outcome(Status.PASS, "包名关键字扫描无命中", evidence)
        }
    }

    /** 4. 未知来源安装开关 */
    fun unknownSources(context: Context): Outcome {
        val global = runCatching {
            Settings.Global.getInt(context.contentResolver, Settings.Global.INSTALL_NON_MARKET_APPS)
        }.getOrDefault(-1)
        val secure = runCatching {
            Settings.Secure.getInt(context.contentResolver, "install_non_market_apps")
        }.getOrDefault(-1)
        val canRequest = runCatching {
            if (android.os.Build.VERSION.SDK_INT >= android.os.Build.VERSION_CODES.O) {
                context.packageManager.canRequestPackageInstalls()
            } else null
        }.getOrNull()
        val evidence = listOf(
            "Settings.Global.INSTALL_NON_MARKET_APPS = $global",
            "Settings.Secure.install_non_market_apps = $secure",
            "canRequestPackageInstalls = $canRequest"
        )
        val on = global == 1 || secure == 1
        return if (on) {
            Outcome(Status.WARN, "允许安装未知来源应用", evidence)
        } else {
            Outcome(Status.PASS, "未开启未知来源安装", evidence)
        }
    }

    /** 5. shell 侧全量包名扫描（补充 PackageManager 可见性限制） */
    fun shellPackages(): Outcome {
        val out = Shell.out("pm list packages 2>/dev/null | head -n 500", 3000)
        val names = out.lines().mapNotNull { l ->
            val i = l.indexOf(':')
            if (i >= 0) l.substring(i + 1).trim() else null
        }
        if (names.isEmpty()) {
            return Outcome(Status.INFO, "shell 无法列出包名（正常限制）", listOf("pm list packages 无输出"))
        }
        val hit = names.filter { n ->
            val s = n.lowercase()
            KnownLists.PACKAGE_KEYWORDS.any { s.contains(it) }
        }
        val evidence = mutableListOf<String>()
        evidence += "shell 可见包数量: ${names.size}"
        evidence += hit.ifEmpty { listOf("无关键字命中") }
        return if (hit.isNotEmpty()) {
            Outcome(Status.WARN, "shell 侧发现 ${hit.size} 个风险关键字包名", evidence)
        } else {
            Outcome(Status.PASS, "shell 侧包名扫描无命中", evidence)
        }
    }
}
