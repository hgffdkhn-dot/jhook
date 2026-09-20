package com.detect.integrity.detection

import android.content.Context
import androidx.preference.PreferenceManager
import com.detect.integrity.model.CheckResult
import com.detect.integrity.model.CheckSpec
import com.detect.integrity.model.Outcome
import com.detect.integrity.model.Score
import com.detect.integrity.model.Status
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext

/**
 * 检测引擎：串行执行所有已启用的检测项（避免并发 shell 造成误判），并计算评分。
 */
object DetectionEngine {

    suspend fun run(
        context: Context,
        onProgress: suspend (done: Int, total: Int, title: String) -> Unit
    ): List<CheckResult> = withContext(Dispatchers.IO) {
        val specs = CheckRegistry.enabled(context)
        val results = ArrayList<CheckResult>(specs.size)
        specs.forEachIndexed { index, spec ->
            withContext(Dispatchers.Main) { onProgress(index + 1, specs.size, spec.title) }
            val start = System.currentTimeMillis()
            val outcome: Outcome = try {
                spec.block()
            } catch (e: Throwable) {
                Outcome(
                    Status.ERROR,
                    "检测失败：${e.message ?: e.javaClass.simpleName}",
                    listOf(e.stackTraceToString().take(800))
                )
            }
            results += CheckResult(
                id = spec.id,
                title = spec.title,
                category = spec.category,
                status = outcome.status,
                summary = outcome.summary,
                evidence = outcome.evidence,
                weight = spec.weight,
                durationMs = System.currentTimeMillis() - start
            )
        }
        results
    }

    suspend fun runSingle(context: Context, spec: CheckSpec): CheckResult = withContext(Dispatchers.IO) {
        val start = System.currentTimeMillis()
        val outcome = try {
            spec.block()
        } catch (e: Throwable) {
            Outcome(
                Status.ERROR,
                "检测失败：${e.message ?: e.javaClass.simpleName}",
                listOf(e.stackTraceToString().take(800))
            )
        }
        CheckResult(
            id = spec.id,
            title = spec.title,
            category = spec.category,
            status = outcome.status,
            summary = outcome.summary,
            evidence = outcome.evidence,
            weight = spec.weight,
            durationMs = System.currentTimeMillis() - start
        )
    }

    fun score(context: Context, results: List<CheckResult>): Score {
        val strict = PreferenceManager.getDefaultSharedPreferences(context)
            .getBoolean("pref_strict_mode", false)

        var pass = 0
        var info = 0
        var warn = 0
        var danger = 0
        var error = 0
        var totalWeight = 0
        var riskWeight = 0.0

        for (r in results) {
            when (r.status) {
                Status.PASS -> pass++
                Status.INFO -> info++
                Status.WARN -> warn++
                Status.DANGER -> danger++
                Status.ERROR -> error++
                Status.SKIP -> Unit
            }
            totalWeight += r.weight
            riskWeight += when (r.status) {
                Status.DANGER -> r.weight.toDouble()
                Status.WARN -> r.weight * 0.4
                Status.ERROR -> r.weight * 0.1
                else -> 0.0
            }
        }

        val risk = if (totalWeight == 0) 0 else (riskWeight / totalWeight * 100).toInt().coerceIn(0, 100)
        val trust = 100 - risk
        val passed = danger == 0 && !(strict && warn > 0)
        val verdict = when {
            danger > 0 -> "检测到 $danger 项高风险（疑似已 root / 系统被修改）"
            strict && warn > 0 -> "存在 $warn 项可疑迹象（严格模式下判定为不通过）"
            warn > 0 -> "基本完整，但有 $warn 项可疑迹象"
            error > 0 -> "检测完成，其中 $error 项执行失败"
            else -> "未发现篡改迹象"
        }
        return Score(
            trust = trust,
            risk = risk,
            pass = pass,
            info = info,
            warn = warn,
            danger = danger,
            error = error,
            total = results.size,
            verdict = verdict,
            passed = passed
        )
    }
}
