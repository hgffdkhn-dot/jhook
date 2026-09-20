package com.detect.integrity.model

/**
 * 检测类别。UI 上的分组顺序即为枚举顺序。
 */
enum class Category(val id: String, val title: String, val desc: String) {
    ROOT("root", "Root 与 su", "su 二进制、root 授权管理、系统目录可写"),
    MAGISK("magisk", "Magisk / Systemless", "Magisk App、模块目录、Zygisk、tmpfs 挂载"),
    MOUNT("mount", "系统挂载", "分区读写属性、tmpfs / overlay 覆盖、可疑挂载点"),
    PACKAGE("package", "风险应用", "root 授权管理、root 隐藏、注入与多开类应用"),
    HOOK("hook", "注入与 Hook", "Xposed / LSPosed / Riru / Zygisk / Frida 注入痕迹"),
    INTEGRITY("integrity", "系统完整性", "Verified Boot、vbmeta、dm-verity、SELinux、构建指纹"),
    GOOGLE_CERT("google_cert", "谷歌证书与 GMS", "系统信任库 Google 根证书、GMS / 应用商店签名"),
    SIGNATURE("signature", "应用自身完整性", "签名指纹、安装来源、可调试标志、APK 路径"),
    DEBUGGER("debugger", "调试与开发者选项", "调试器附加、ADB、开发者选项、可调试属性"),
    EMULATOR("emulator", "模拟器 / 虚拟环境", "QEMU、Genymotion、云手机等特征"),
    PLAY_INTEGRITY("play_integrity", "Play Integrity", "Google Play 设备与应用完整性判定")
}

enum class Status {
    /** 未发现异常 */
    PASS,

    /** 中性提示信息 */
    INFO,

    /** 可疑，需人工确认 */
    WARN,

    /** 明确检出风险 */
    DANGER,

    /** 检测过程中出错 */
    ERROR,

    /** 被设置跳过 */
    SKIP;

    val isRisk: Boolean get() = this == DANGER
    val isSuspicious: Boolean get() = this == WARN
}

data class CheckResult(
    val id: String,
    val title: String,
    val category: Category,
    val status: Status,
    val summary: String,
    val evidence: List<String> = emptyList(),
    val weight: Int = 1,
    val durationMs: Long = 0
)

/** 单项检测的产出，不含元数据（元数据由注册表中的 CheckSpec 提供） */
data class Outcome(
    val status: Status,
    val summary: String,
    val evidence: List<String> = emptyList()
)

data class CheckSpec(
    val id: String,
    val title: String,
    val category: Category,
    val description: String,
    val weight: Int = 1,
    /** 耗时项目（全目录扫描、端口扫描等），设置里可跳过 */
    val slow: Boolean = false,
    /** 需要网络 / Google Play 服务 */
    val needsPlay: Boolean = false,
    val block: suspend () -> Outcome
)

/** 整体评分 */
data class Score(
    val trust: Int,
    val risk: Int,
    val pass: Int,
    val info: Int,
    val warn: Int,
    val danger: Int,
    val error: Int,
    val total: Int,
    val verdict: String,
    val passed: Boolean
)
