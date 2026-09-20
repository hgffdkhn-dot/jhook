package com.detect.integrity.detection

import android.content.Context
import android.util.Base64
import com.detect.integrity.BuildConfig
import com.detect.integrity.model.Outcome
import com.detect.integrity.model.Status
import com.google.android.gms.common.ConnectionResult
import com.google.android.gms.common.GoogleApiAvailability
import com.google.android.gms.tasks.Task
import com.google.android.play.core.integrity.IntegrityManagerFactory
import com.google.android.play.core.integrity.IntegrityTokenRequest
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.suspendCancellableCoroutine
import kotlinx.coroutines.withContext
import org.json.JSONArray
import org.json.JSONObject
import java.io.OutputStreamWriter
import java.net.HttpURLConnection
import java.net.URL
import java.security.SecureRandom
import kotlin.coroutines.resume
import kotlin.coroutines.resumeWithException

/**
 * Google Play Integrity 检测。
 *
 * 说明：Integrity 令牌是加密的，真正可信的判定需要在**你自己的服务端**调用 Google 接口解密。
 * 因此这里支持三种用法：
 *  1. 只取令牌（未配置服务端地址）→ 结果为 INFO；
 *  2. 配置服务端解密地址 → 把令牌 POST 过去，解析返回的 JSON 判定；
 *  3. 未启用/无 GMS → SKIP。
 */
object PlayIntegrityCheck {

    suspend fun run(
        context: Context,
        enabled: Boolean,
        cloudProject: String,
        endpoint: String
    ): Outcome = withContext(Dispatchers.IO) {
        if (!enabled) {
            return@withContext Outcome(
                Status.SKIP,
                "已在设置中关闭 Play Integrity 检测",
                listOf("如需启用：设置 → 谷歌证书与 Play Integrity → 开启并填写云端项目号")
            )
        }
        val project = cloudProject.trim().toLongOrNull()
            ?: BuildConfig.PLAY_CLOUD_PROJECT_NUMBER.takeIf { it > 0L }
        if (project == null) {
            return@withContext Outcome(
                Status.WARN,
                "未配置云端项目号，无法请求 Integrity 令牌",
                listOf(
                    "请在设置中填入 Google Cloud 项目号（Play 管理中心 → 应用完整性 中绑定后的项目号）",
                    "也可以在 app/build.gradle.kts 的 PLAY_CLOUD_PROJECT_NUMBER 中预置"
                )
            )
        }

        val gms = try {
            GoogleApiAvailability.getInstance().isGooglePlayServicesAvailable(context)
        } catch (e: Exception) {
            -1
        }
        if (gms != ConnectionResult.SUCCESS) {
            return@withContext Outcome(
                Status.WARN,
                "Google Play 服务不可用，跳过 Integrity 检测（code=$gms）",
                listOf("无 GMS 的设备（如国行 ROM）无法使用 Play Integrity")
            )
        }

        val nonce = generateNonce()
        val token = try {
            val manager = IntegrityManagerFactory.create(context)
            val request = IntegrityTokenRequest.builder()
                .setCloudProjectNumber(project)
                .setNonce(nonce)
                .build()
            manager.requestIntegrityToken(request).awaitTask().token()
        } catch (e: Exception) {
            return@withContext Outcome(
                Status.ERROR,
                "请求 Integrity 令牌失败: ${e.message}",
                listOf(
                    e.javaClass.simpleName,
                    "常见原因：项目号与包名不匹配、未在 Play 管理中心启用 Integrity、网络不可用"
                )
            )
        }

        val evidence = mutableListOf<String>()
        evidence += "云端项目号: $project"
        evidence += "一次性随机数(nonce): $nonce"
        evidence += "令牌长度: ${token.length}"
        evidence += "令牌前缀: ${token.take(48)}…"

        // 1) 尝试本地直接解析（部分情况下 payload 可读）
        val local = decodePayload(token)
        if (local != null) {
            evidence += "本地解析 payload: ${local.toString().take(600)}"
            val mapped = mapVerdict(local)
            if (mapped != null) return@withContext mapped.copy(evidence = mapped.evidence + evidence)
        }

        // 2) 走服务端解密
        val url = endpoint.trim().ifBlank { BuildConfig.INTEGRITY_DECRYPT_ENDPOINT }
        if (url.isBlank()) {
            return@withContext Outcome(
                Status.INFO,
                "已获取 Integrity 令牌，需服务端解密后才能判定",
                evidence + listOf(
                    "请在设置中填写“服务端解密地址”，服务端需调用 Google 的 decodeIntegrityToken 接口",
                    "参考：https://developer.android.com/google/play/integrity/verdicts"
                )
            )
        }
        return@withContext try {
            val body = postToken(url, token)
            evidence += "服务端返回: ${body.take(800)}"
            val json = JSONObject(body)
            val mapped = mapVerdict(json)
                ?: return@withContext Outcome(Status.INFO, "服务端未返回可识别的判定字段", evidence)
            mapped.copy(evidence = mapped.evidence + evidence)
        } catch (e: Exception) {
            Outcome(Status.ERROR, "服务端解密失败: ${e.message}", evidence)
        }
    }

    private fun decodePayload(token: String): JSONObject? {
        val parts = token.split(".")
        if (parts.size < 2) return null
        return try {
            val bytes = Base64.decode(parts[1], Base64.URL_SAFE or Base64.NO_WRAP or Base64.NO_PADDING)
            val json = JSONObject(String(bytes))
            if (json.has("deviceRecognitionVerdict") || json.has("basicIntegrity") || json.has("ctsProfileMatch")) {
                json
            } else null
        } catch (_: Exception) {
            null
        }
    }

    private fun mapVerdict(json: JSONObject): Outcome? {
        val device = json.opt("deviceRecognitionVerdict")
        val verdicts = mutableListOf<String>()
        when (device) {
            is JSONArray -> for (i in 0 until device.length()) verdicts += device.optString(i)
            is String -> verdicts += device
            is JSONObject -> {
                val arr = device.optJSONArray("verdicts") ?: device.optJSONArray("deviceRecognitionVerdict")
                if (arr != null) for (i in 0 until arr.length()) verdicts += arr.optString(i)
            }
        }

        val evidence = mutableListOf<String>()
        if (verdicts.isNotEmpty()) evidence += "deviceRecognitionVerdict = ${verdicts.joinToString()}"
        json.optString("appRecognitionVerdict").takeIf { it.isNotEmpty() }
            ?.let { evidence += "appRecognitionVerdict = $it" }
        json.optString("accountDetails").takeIf { it.isNotEmpty() }
            ?.let { evidence += "accountDetails = $it" }
        json.optString("requestDetails").takeIf { it.isNotEmpty() }
            ?.let { evidence += "requestDetails = $it" }
        json.opt("basicIntegrity")?.let { evidence += "basicIntegrity = $it" }
        json.opt("ctsProfileMatch")?.let { evidence += "ctsProfileMatch = $it" }
        json.optString("advice").takeIf { it.isNotEmpty() }?.let { evidence += "advice = $it" }

        val status: Status
        val summary: String
        when {
            verdicts.contains("MEETS_STRONG_INTEGRITY") -> {
                status = Status.PASS
                summary = "Play Integrity：MEETS_STRONG_INTEGRITY（最高等级）"
            }
            verdicts.contains("MEETS_DEVICE_INTEGRITY") -> {
                status = Status.PASS
                summary = "Play Integrity：MEETS_DEVICE_INTEGRITY（设备通过完整性校验）"
            }
            verdicts.contains("MEETS_VIRTUAL_INTEGRITY") -> {
                status = Status.WARN
                summary = "Play Integrity：MEETS_VIRTUAL_INTEGRITY（模拟器/虚拟环境）"
            }
            verdicts.contains("MEETS_BASIC_INTEGRITY") -> {
                status = Status.WARN
                summary = "Play Integrity：MEETS_BASIC_INTEGRITY（仅基础完整性，未通过 CTS）"
            }
            verdicts.isNotEmpty() -> {
                status = Status.DANGER
                summary = "Play Integrity：未通过（${verdicts.joinToString()}）"
            }
            json.opt("ctsProfileMatch") == true -> {
                status = Status.PASS
                summary = "SafetyNet/Integrity：ctsProfileMatch=true"
            }
            json.opt("basicIntegrity") == true -> {
                status = Status.WARN
                summary = "basicIntegrity=true，但 ctsProfileMatch=false"
            }
            json.opt("basicIntegrity") == false -> {
                status = Status.DANGER
                summary = "basicIntegrity=false（设备未通过完整性校验）"
            }
            else -> return null
        }
        return Outcome(status, summary, evidence)
    }

    private fun generateNonce(): String {
        val bytes = ByteArray(32)
        SecureRandom().nextBytes(bytes)
        return Base64.encodeToString(bytes, Base64.URL_SAFE or Base64.NO_WRAP or Base64.NO_PADDING).take(44)
    }

    private fun postToken(endpoint: String, token: String): String {
        val conn = URL(endpoint).openConnection() as HttpURLConnection
        return try {
            conn.requestMethod = "POST"
            conn.doOutput = true
            conn.connectTimeout = 8000
            conn.readTimeout = 8000
            conn.setRequestProperty("Content-Type", "application/json")
            OutputStreamWriter(conn.outputStream, Charsets.UTF_8).use {
                it.write(JSONObject().put("token", token).toString())
                it.flush()
            }
            val code = conn.responseCode
            val stream = if (code in 200..299) conn.inputStream else conn.errorStream
            val body = stream?.bufferedReader(Charsets.UTF_8)?.readText() ?: ""
            "HTTP $code: $body"
        } finally {
            conn.disconnect()
        }
    }

    private suspend fun <T> Task<T>.awaitTask(): T = suspendCancellableCoroutine { cont ->
        addOnSuccessListener { result -> cont.resume(result) }
        addOnFailureListener { e -> cont.resumeWithException(e) }
        addOnCanceledListener { if (cont.isActive) cont.cancel() }
    }
}
