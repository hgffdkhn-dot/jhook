package com.detect.integrity.detection

import android.app.ActivityManager
import android.content.Context
import android.os.Debug
import android.provider.Settings
import com.detect.integrity.model.Outcome
import com.detect.integrity.model.Status
import com.detect.integrity.util.Proc
import com.detect.integrity.util.Props

/**
 * 调试器与开发者选项检测
 */
object DebugChecks {

    /** 1. 调试器是否附加 */
    fun attached(): Outcome {
        val connected = Debug.isDebuggerConnected()
        val waiting = try {
            Debug.waitingForDebugger()
        } catch (_: Exception) {
            false
        }
        val evidence = listOf(
            "Debug.isDebuggerConnected = $connected",
            "Debug.waitingForDebugger = $waiting"
        )
        return if (connected || waiting) {
            Outcome(Status.WARN, "检测到调试器连接", evidence)
        } else {
            Outcome(Status.PASS, "无调试器附加", evidence)
        }
    }

    /** 2. TracerPid（被 ptrace 附加） */
    fun tracerPid(): Outcome {
        val pid = Proc.statusField("TracerPid")
        val state = Proc.statusField("State")
        val evidence = listOf(
            "TracerPid = ${pid ?: "(无法读取)"}",
            "State = ${state ?: "(无法读取)"}",
            "说明：TracerPid != 0 表示本进程被调试器/注入工具跟踪"
        )
        val v = pid?.toIntOrNull()
        return when {
            v == null -> Outcome(Status.INFO, "无法读取 /proc/self/status", evidence)
            v != 0 -> Outcome(Status.DANGER, "本进程被跟踪（TracerPid=$v）", evidence)
            else -> Outcome(Status.PASS, "未被 ptrace 跟踪", evidence)
        }
    }

    /** 3. ADB 调试开关 */
    fun adb(context: Context): Outcome {
        val adb = runCatching {
            Settings.Global.getInt(context.contentResolver, Settings.Global.ADB_ENABLED)
        }.getOrDefault(-1)
        val adbWifi = runCatching {
            Settings.Global.getInt(context.contentResolver, "adb_wifi_enabled")
        }.getOrDefault(-1)
        val propAdb = Props.get("persist.sys.usb.config")
        val evidence = listOf(
            "Settings.Global.ADB_ENABLED = $adb",
            "adb_wifi_enabled = $adbWifi",
            "persist.sys.usb.config = ${propAdb.ifEmpty { "(无)" }}",
            "init.svc.adbd = ${Props.get("init.svc.adbd")}"
        )
        return when (adb) {
            1 -> Outcome(Status.WARN, "USB 调试已开启", evidence)
            0 -> Outcome(Status.PASS, "USB 调试未开启", evidence)
            else -> Outcome(Status.INFO, "无法读取 ADB 状态", evidence)
        }
    }

    /** 4. 开发者选项 / root 调试属性 */
    fun devOptions(context: Context): Outcome {
        val dev = runCatching {
            Settings.Global.getInt(context.contentResolver, Settings.Global.DEVELOPMENT_SETTINGS_ENABLED)
        }.getOrDefault(-1)
        val stayAwake = runCatching {
            Settings.Global.getInt(context.contentResolver, Settings.Global.STAY_ON_WHILE_PLUGGED_IN)
        }.getOrDefault(-1)
        val evidence = listOf(
            "development_settings_enabled = $dev",
            "stay_on_while_plugged_in = $stayAwake",
            "ro.debuggable = ${Props.get("ro.debuggable")}",
            "service.adb.root = ${Props.get("service.adb.root")}",
            "persist.sys.root_access = ${Props.get("persist.sys.root_access")}"
        )
        val risky = Props.get("service.adb.root") == "1" || Props.get("persist.sys.root_access") == "1"
        return when {
            risky -> Outcome(Status.DANGER, "系统以 root 权限运行 adbd", evidence)
            dev == 1 -> Outcome(Status.WARN, "开发者选项已开启", evidence)
            dev == 0 -> Outcome(Status.PASS, "开发者选项未开启", evidence)
            else -> Outcome(Status.INFO, "无法读取开发者选项状态", evidence)
        }
    }

    /** 5. 自动化测试 / 脚本环境 */
    fun automation(context: Context): Outcome {
        val am = context.getSystemService(Context.ACTIVITY_SERVICE) as? ActivityManager
        val monkey = try {
            ActivityManager.isUserAMonkey()
        } catch (_: Exception) {
            false
        }
        val runningProcesses = am?.runningAppProcesses?.size ?: -1
        val evidence = listOf(
            "ActivityManager.isUserAMonkey = $monkey",
            "runningAppProcesses = $runningProcesses",
            "ro.test_harness = ${Props.get("ro.test_harness")}"
        )
        return if (monkey || Props.get("ro.test_harness") == "1") {
            Outcome(Status.WARN, "处于自动化测试环境", evidence)
        } else {
            Outcome(Status.PASS, "非自动化测试环境", evidence)
        }
    }
}
