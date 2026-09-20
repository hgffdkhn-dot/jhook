package com.detect.integrity.model

/**
 * 各类已知特征库。可自行往列表里追加内容，改完重新编译即可。
 */
object KnownLists {

    /** 常见 su / 授权管理相关文件路径 */
    val SU_PATHS = listOf(
        "/system/app/Superuser.apk",
        "/system/app/Superuser/Superuser.apk",
        "/system/app/Kinguser.apk",
        "/system/bin/su",
        "/system/bin/.ext/.su",
        "/system/bin/ext/su",
        "/system/bin/daemonsu",
        "/system/bin/sugote",
        "/system/bin/sugote-mksh",
        "/system/bin/su2",
        "/system/sbin/su",
        "/system/sd/xbin/su",
        "/system/su",
        "/system/usr/we-need-root/su",
        "/system/xbin/su",
        "/system/xbin/mu",
        "/system/xbin/daemonsu",
        "/system/xbin/sugote",
        "/system/xbin/su2",
        "/system/etc/init.d/99SuperSUDaemon",
        "/system/etc/.has_su_daemon",
        "/system/etc/.installed_su_daemon",
        "/sbin/su",
        "/dev/su",
        "/data/local/su",
        "/data/local/bin/su",
        "/data/local/xbin/su",
        "/data/local/tmp/su",
        "/data/su",
        "/su/bin/su",
        "/su/bin/sugote",
        "/cache/su",
        "/cache/.supersu"
    )

    /** Magisk / KernelSU / APatch 等 systemless 方案的路径 */
    val MAGISK_PATHS = listOf(
        "/data/adb/magisk",
        "/data/adb/magisk.db",
        "/data/adb/magisk.img",
        "/data/adb/magisk_simple",
        "/data/adb/modules",
        "/data/adb/ksu",
        "/data/adb/ksud",
        "/data/adb/ap",
        "/data/adb/apd",
        "/data/adb/.magisk",
        "/data/adb/.config",
        "/data/adb/magiskinit",
        "/sbin/.magisk",
        "/sbin/.core",
        "/sbin/magiskinit",
        "/cache/magisk",
        "/cache/magisk.log",
        "/cache/.disable_magisk",
        "/dev/magisk",
        "/dev/zygisk",
        "/dev/zygisk32",
        "/dev/zygisk64",
        "/debug_ramdisk/magiskinit",
        "/system/etc/init/magisk",
        "/system/etc/init/magisk.rc",
        "/system/bin/magisk",
        "/system/bin/magiskinit",
        "/system/bin/magiskpolicy",
        "/system/bin/magiskboot",
        "/system/bin/ksud",
        "/system/xbin/magisk",
        "/data/local/magisk",
        "/data/unencrypted/magisk",
        "/metadata/magisk",
        "/persist/magisk"
    )

    /** Magisk 管理器包名（含常见 fork / 分身改名） */
    val MAGISK_PACKAGES = listOf(
        "com.topjohnwu.magisk",
        "io.github.huskydg.magisk",
        "com.magisk.manager",
        "io.github.vvb2060.magisk",
        "me.weishu.kernelsu",
        "me.bmax.apatch"
    )

    /** root 授权管理 / 一键 root / root 隐藏类包名 */
    val ROOT_PACKAGES = listOf(
        "com.noshufou.android.su",
        "com.noshufou.android.su.elite",
        "eu.chainfire.supersu",
        "eu.chainfire.supersu.pro",
        "com.koushikdutta.superuser",
        "com.thirdparty.superuser",
        "com.yellowes.su",
        "com.kingroot.kinguser",
        "com.kingroot.master",
        "com.kingo.root",
        "com.mgyun.shua.su",
        "com.geohot.towelroot",
        "com.zachspong.temprootremovejb",
        "com.devadvance.rootcloak",
        "com.devadvance.rootcloakplus",
        "com.amphoras.hidemyroot",
        "com.formyhm.hideroot",
        "com.formyhm.hiderootpremium",
        "com.schurich.android.tools.rootverifier",
        "com.qihoo.root"
    )

    /** Hook / 注入框架及其管理器 */
    val HOOK_PACKAGES = listOf(
        "de.robv.android.xposed.installer",
        "org.lsposed.manager",
        "org.meowcat.edxposed.manager",
        "io.va.exposed",
        "com.taichi.android",
        "com.xposed.installer",
        "me.weishu.epic",
        "me.weishu.exposed",
        "com.saurik.substrate",
        "com.elderdrivers.riru",
        "com.android.zgyd",
        "com.sudocode.hook",
        "com.frida.server"
    )

    /** 已安装包名里出现即视为可疑的关键字 */
    val PACKAGE_KEYWORDS = listOf(
        "magisk", "supersu", "superuser", "xposed", "lsposed", "lspatch",
        "edxposed", "taichi", "riru", "zygisk", "shamiko", "kernelsu",
        "apatch", "frida", "rootcloak", "hideroot", "root", "substrate",
        "epic", "dual", "parallel", "clone", "virtualapp", "shelter"
    )

    /** /proc/self/maps 中出现即视为注入/可疑的关键字 */
    val MAPS_KEYWORDS = listOf(
        "xposed", "xposedbridge", "libxposed", "libepic", "libwhale", "libdobby",
        "libriru", "riru", "zygisk", "libzygisk", "memfd:zygisk", "magisk",
        "frida", "frida-agent", "libfrida", "substrate", "libsubstrate",
        "inject", "libinject", "libhook", "sandhook", "pine", "libmmap"
    )

    /** 系统目录中扫描的可疑文件名关键字 */
    val SUSPICIOUS_FILE_KEYWORDS = listOf(
        "su", "magisk", "magiskinit", "magiskpolicy", "magiskboot", "busybox",
        "daemonsu", "supersu", "superuser", "frida", "xposed", "zygisk", "riru",
        "kernelsu", "ksud", "apatch", "99supersudaemon", "toybox", "nativesu"
    )

    /** 需要关注的分区挂载点 */
    val SYSTEM_MOUNT_POINTS = listOf(
        "/system", "/system_ext", "/vendor", "/product", "/odm", "/oem",
        "/apex", "/boot", "/dtbo", "/vbmeta", "/data", "/sbin", "/", "/bin", "/xbin"
    )

    /** Frida / 调试常用端口 */
    val DEBUG_PORTS = listOf(27042, 27043, 27047, 5555, 21500, 23946)

    /** Google 相关根证书主体关键字（用于系统信任库检查） */
    val GOOGLE_CA_KEYWORDS = listOf(
        "google trust services", "google internet authority", "gts root", "gts ca",
        "globalsign", "google"
    )
}
