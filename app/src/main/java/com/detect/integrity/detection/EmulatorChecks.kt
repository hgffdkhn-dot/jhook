package com.detect.integrity.detection

import android.content.Context
import android.content.pm.PackageManager
import android.os.Build
import com.detect.integrity.model.Outcome
import com.detect.integrity.model.Status
import com.detect.integrity.util.Fs
import com.detect.integrity.util.Props

/**
 * 模拟器 / 虚拟环境 / 云手机检测
 */
object EmulatorChecks {

    private val EMU_PRODUCTS = listOf(
        "sdk", "sdk_gphone", "sdk_gphone64", "emulator", "vbox86p", "vbox86tp",
        "goldfish", "ranchu", "generic", "generic_x86", "generic_x86_64", "droid4x",
        "andy", "nox", "ttvm", "duos", "bluestacks", "genymotion", "ldplayer", "mumu"
    )

    /** 1. Build 字段特征 */
    fun buildFields(): Outcome {
        val fields = listOf(
            "FINGERPRINT" to Build.FINGERPRINT,
            "MODEL" to Build.MODEL,
            "MANUFACTURER" to Build.MANUFACTURER,
            "BRAND" to Build.BRAND,
            "DEVICE" to Build.DEVICE,
            "PRODUCT" to Build.PRODUCT,
            "HARDWARE" to Build.HARDWARE,
            "BOARD" to Build.BOARD,
            "HOST" to Build.HOST,
            "USER" to Build.USER
        )
        val hits = fields.filter { (_, v) ->
            val s = v.lowercase()
            EMU_PRODUCTS.any { s.contains(it) }
        }
        val evidence = fields.map { "${it.first} = ${it.second}" }
        return if (hits.isNotEmpty()) {
            Outcome(Status.DANGER, "Build 字段命中模拟器特征: ${hits.map { it.first }.joinToString()}", evidence)
        } else {
            Outcome(Status.PASS, "Build 字段无模拟器特征", evidence)
        }
    }

    /** 2. QEMU 相关属性 */
    fun qemuProps(): Outcome {
        val keys = listOf(
            "ro.kernel.qemu", "ro.hardware", "ro.boot.hardware", "ro.product.device",
            "init.svc.qemud", "init.svc.qemu-props", "qemu.hw.mainkeys",
            "ro.boot.qemu", "ro.build.host", "ro.bootimage.build.fingerprint",
            "ro.system.build.fingerprint", "ro.product.cpu.abi"
        )
        val evidence = keys.map { "$it = ${Props.get(it).ifEmpty { "(无)" }}" }
        val qemu = Props.get("ro.kernel.qemu")
        val hw = Props.get("ro.hardware").lowercase()
        val goldfish = hw.contains("goldfish") || hw.contains("ranchu") || hw.contains("vbox")
        val svc = Props.get("init.svc.qemud")
        return when {
            qemu == "1" || svc.isNotEmpty() -> Outcome(Status.DANGER, "检测到 QEMU 运行环境", evidence)
            goldfish -> Outcome(Status.DANGER, "硬件为模拟器平台: ${Props.get("ro.hardware")}", evidence)
            else -> Outcome(Status.PASS, "无 QEMU 属性特征", evidence)
        }
    }

    /** 3. 模拟器设备文件 */
    fun qemuFiles(): Outcome {
        val paths = listOf(
            "/dev/socket/qemud", "/dev/qemu_pipe", "/dev/goldfish_pipe",
            "/system/lib/libc_malloc_debug_qemu.so", "/sys/qemu_trace",
            "/system/bin/qemu-props", "/dev/socket/genyd", "/dev/socket/baseband_genyd",
            "/proc/tty/drivers", "/system/lib/libdroid4x.so", "/system/etc/init.vbox.rc"
        )
        val found = paths.filter { Fs.exists(it) }
        val evidence = found.map { "存在: $it" }
            .ifEmpty { listOf("未发现模拟器特征文件（已检查 ${paths.size} 个路径）") }
        return if (found.isNotEmpty()) {
            Outcome(Status.DANGER, "发现 ${found.size} 个模拟器特征文件", evidence)
        } else {
            Outcome(Status.PASS, "无模拟器特征文件", evidence)
        }
    }

    /** 4. 硬件特性缺失 */
    fun features(context: Context): Outcome {
        val feats = listOf(
            PackageManager.FEATURE_TELEPHONY,
            PackageManager.FEATURE_BLUETOOTH,
            PackageManager.FEATURE_CAMERA,
            PackageManager.FEATURE_SENSOR_GYROSCOPE,
            PackageManager.FEATURE_LOCATION_GPS
        )
        val pm = context.packageManager
        val missing = mutableListOf<String>()
        val evidence = mutableListOf<String>()
        for (f in feats) {
            val has = pm.hasSystemFeature(f)
            evidence += "$f = $has"
            if (!has) missing += f
        }
        return when {
            missing.size >= 2 -> Outcome(Status.WARN, "缺失 ${missing.size} 项硬件特性（模拟器常见）", evidence)
            missing.size == 1 -> Outcome(Status.INFO, "缺失 ${missing.first()}", evidence)
            else -> Outcome(Status.PASS, "硬件特性完整", evidence)
        }
    }

    /** 5. 传感器与基带（补充） */
    fun sensors(context: Context): Outcome {
        val sm = context.getSystemService(Context.SENSOR_SERVICE) as? android.hardware.SensorManager
        val list = sm?.getSensorList(android.hardware.Sensor.TYPE_ALL) ?: emptyList()
        val evidence = mutableListOf<String>()
        evidence += "传感器数量: ${list.size}"
        list.take(12).forEach { evidence += "  ${it.name} (${it.vendor})" }
        return if (list.isEmpty()) {
            Outcome(Status.WARN, "无任何传感器（模拟器常见）", evidence)
        } else {
            Outcome(Status.PASS, "传感器数量 ${list.size}", evidence)
        }
    }
}
