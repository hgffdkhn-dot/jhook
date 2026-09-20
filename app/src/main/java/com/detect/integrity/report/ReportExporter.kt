package com.detect.integrity.report

import android.os.Build
import com.detect.integrity.model.CheckResult
import com.detect.integrity.model.Score
import com.detect.integrity.model.Status
import com.detect.integrity.util.Props
import org.json.JSONArray
import org.json.JSONObject
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale

object ReportExporter {

    fun deviceInfo(): LinkedHashMap<String, String> {
        val m = LinkedHashMap<String, String>()
        m["manufacturer"] = Build.MANUFACTURER
        m["brand"] = Build.BRAND
        m["model"] = Build.MODEL
        m["device"] = Build.DEVICE
        m["product"] = Build.PRODUCT
        m["hardware"] = Build.HARDWARE
        m["board"] = Build.BOARD
        m["android"] = "${Build.VERSION.RELEASE} (API ${Build.VERSION.SDK_INT})"
        m["build_id"] = Build.ID
        m["build_type"] = Build.TYPE
        m["build_tags"] = Build.TAGS ?: ""
        m["fingerprint"] = Build.FINGERPRINT
        m["security_patch"] = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.M) Build.VERSION.SECURITY_PATCH else ""
        m["bootloader"] = Build.BOOTLOADER
        m["kernel"] = System.getProperty("os.version") ?: ""
        m["abi"] = Build.SUPPORTED_ABIS.joinToString()
        m["ro.boot.vbmeta.device_state"] = Props.get("ro.boot.vbmeta.device_state")
        m["ro.boot.verifiedbootstate"] = Props.get("ro.boot.verifiedbootstate")
        m["ro.boot.flash.locked"] = Props.get("ro.boot.flash.locked")
        return m
    }

    private fun time(ts: Long = System.currentTimeMillis()): String =
        SimpleDateFormat("yyyy-MM-dd HH:mm:ss", Locale.getDefault()).format(Date(ts))

    fun toJson(results: List<CheckResult>, score: Score, elapsedMs: Long): String {
        val root = JSONObject()
        root.put("generated_at", time())
        root.put("app", "设备完整性检测")
        root.put("elapsed_ms", elapsedMs)

        val dev = JSONObject()
        deviceInfo().forEach { (k, v) -> dev.put(k, v) }
        root.put("device", dev)

        val sc = JSONObject()
        sc.put("trust", score.trust)
        sc.put("risk", score.risk)
        sc.put("verdict", score.verdict)
        sc.put("passed", score.passed)
        sc.put("pass", score.pass)
        sc.put("info", score.info)
        sc.put("warn", score.warn)
        sc.put("danger", score.danger)
        sc.put("error", score.error)
        sc.put("total", score.total)
        root.put("score", sc)

        val arr = JSONArray()
        for (r in results) {
            val o = JSONObject()
            o.put("id", r.id)
            o.put("title", r.title)
            o.put("category", r.category.id)
            o.put("category_title", r.category.title)
            o.put("status", r.status.name)
            o.put("summary", r.summary)
            o.put("weight", r.weight)
            o.put("duration_ms", r.durationMs)
            val ev = JSONArray()
            r.evidence.forEach { ev.put(it) }
            o.put("evidence", ev)
            arr.put(o)
        }
        root.put("checks", arr)
        return root.toString(2)
    }

    fun toText(results: List<CheckResult>, score: Score, elapsedMs: Long): String {
        val sb = StringBuilder()
        sb.append("设备完整性检测报告\n")
        sb.append("生成时间: ").append(time()).append("\n")
        sb.append("耗时: ").append(elapsedMs).append(" ms\n\n")

        sb.append("【设备信息】\n")
        deviceInfo().forEach { (k, v) -> if (v.isNotEmpty()) sb.append("$k = $v\n") }

        sb.append("\n【结论】\n")
        sb.append("完整性评分: ").append(score.trust).append("/100\n")
        sb.append("风险评分: ").append(score.risk).append("/100\n")
        sb.append("结论: ").append(score.verdict).append("\n")
        sb.append("通过 ").append(score.pass)
            .append(" · 提示 ").append(score.info)
            .append(" · 可疑 ").append(score.warn)
            .append(" · 风险 ").append(score.danger)
            .append(" · 失败 ").append(score.error)
            .append(" （共 ").append(score.total).append(" 项）\n\n")

        val grouped = results.groupBy { it.category }
        for ((cat, items) in grouped) {
            sb.append("【").append(cat.title).append("】\n")
            for (r in items) {
                sb.append("  [").append(statusLabel(r.status)).append("] ")
                    .append(r.title).append(": ").append(r.summary).append("\n")
                if (r.evidence.isNotEmpty() && r.status != Status.PASS) {
                    r.evidence.take(20).forEach { sb.append("      - ").append(it).append("\n") }
                }
            }
            sb.append("\n")
        }
        return sb.toString()
    }

    fun statusLabel(s: Status): String = when (s) {
        Status.PASS -> "正常"
        Status.INFO -> "提示"
        Status.WARN -> "可疑"
        Status.DANGER -> "风险"
        Status.ERROR -> "失败"
        Status.SKIP -> "跳过"
    }
}
