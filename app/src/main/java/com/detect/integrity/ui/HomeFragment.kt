package com.detect.integrity.ui

import android.content.ClipData
import android.content.ClipboardManager
import android.content.Context
import android.content.Intent
import android.os.Bundle
import android.view.View
import android.widget.Toast
import androidx.core.content.FileProvider
import androidx.fragment.app.Fragment
import androidx.lifecycle.lifecycleScope
import com.detect.integrity.R
import com.detect.integrity.databinding.FragmentHomeBinding
import com.detect.integrity.detection.DetectionEngine
import com.detect.integrity.model.Category
import com.detect.integrity.model.CheckResult
import com.detect.integrity.model.Score
import com.detect.integrity.model.Status
import com.detect.integrity.report.ReportExporter
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import java.io.File
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale

class HomeFragment : Fragment(R.layout.fragment_home) {

    private var _b: FragmentHomeBinding? = null
    private val b get() = _b!!

    private lateinit var adapter: ResultAdapter

    private var results: List<CheckResult> = emptyList()
    private var score: Score? = null
    private var running = false
    private var progressText: String? = null
    private var lastScan: String? = null
    private var elapsedMs = 0L
    private val expanded = LinkedHashSet<String>()

    override fun onViewCreated(view: View, savedInstanceState: Bundle?) {
        super.onViewCreated(view, savedInstanceState)
        _b = FragmentHomeBinding.bind(view)

        adapter = ResultAdapter(
            onItemClick = { r ->
                if (!expanded.remove(r.id)) expanded.add(r.id)
                render()
            },
            onScan = { startScan() },
            onExport = { exportReport() },
            onCopy = { copySummary() }
        )
        b.recycler.adapter = adapter
        render()

        if (savedInstanceState == null) startScan()
    }

    private fun startScan() {
        if (running) return
        running = true
        b.progress.show()
        render()
        viewLifecycleOwner.lifecycleScope.launch {
            val start = System.currentTimeMillis()
            val res = DetectionEngine.run(requireContext()) { done, total, title ->
                progressText = "($done/$total) $title"
                render()
            }
            elapsedMs = System.currentTimeMillis() - start
            results = res
            score = DetectionEngine.score(requireContext(), res)
            lastScan = SimpleDateFormat("HH:mm:ss", Locale.getDefault()).format(Date())
            running = false
            progressText = null
            b.progress.hide()
            render()
        }
    }

    private fun render() {
        if (_b == null) return
        adapter.submitList(RowBuilder.build(results, score, running, progressText, lastScan, expanded))
    }

    /** 供顶部工具栏的“导出”按钮调用 */
    fun exportReport() {
        val s = score ?: run {
            Toast.makeText(requireContext(), "请先完成一次检测", Toast.LENGTH_SHORT).show()
            return
        }
        viewLifecycleOwner.lifecycleScope.launch(Dispatchers.IO) {
            try {
                val dir = File(requireContext().cacheDir, "reports")
                if (!dir.exists()) dir.mkdirs()
                val file = File(dir, "device_integrity_${System.currentTimeMillis()}.json")
                file.writeText(ReportExporter.toJson(results, s, elapsedMs))
                val uri = FileProvider.getUriForFile(
                    requireContext(),
                    "${requireContext().packageName}.fileprovider",
                    file
                )
                withContext(Dispatchers.Main) {
                    val intent = Intent(Intent.ACTION_SEND).apply {
                        type = "application/json"
                        putExtra(Intent.EXTRA_STREAM, uri)
                        putExtra(Intent.EXTRA_SUBJECT, "设备完整性检测报告")
                        addFlags(Intent.FLAG_GRANT_READ_URI_PERMISSION)
                    }
                    startActivity(Intent.createChooser(intent, getString(R.string.action_export)))
                }
            } catch (e: Exception) {
                withContext(Dispatchers.Main) {
                    Toast.makeText(
                        requireContext(),
                        getString(R.string.export_failed, e.message ?: ""),
                        Toast.LENGTH_SHORT
                    ).show()
                }
            }
        }
    }

    private fun copySummary() {
        val s = score ?: return
        val text = ReportExporter.toText(results, s, elapsedMs)
        val cm = requireContext().getSystemService(Context.CLIPBOARD_SERVICE) as ClipboardManager
        cm.setPrimaryClip(ClipData.newPlainText("device_integrity_report", text))
        Toast.makeText(requireContext(), R.string.copied, Toast.LENGTH_SHORT).show()
    }

    override fun onDestroyView() {
        super.onDestroyView()
        _b = null
    }
}

/** 把结果整理成首页列表行 */
object RowBuilder {
    fun build(
        results: List<CheckResult>,
        score: Score?,
        running: Boolean,
        progressText: String?,
        lastScan: String?,
        expanded: Set<String>
    ): List<Row> {
        val rows = mutableListOf<Row>()
        rows += Row.Summary(score, running, progressText, lastScan)
        if (results.isEmpty()) return rows
        for (cat in Category.values()) {
            val items = results.filter { it.category == cat }
            if (items.isEmpty()) continue
            rows += Row.Header(
                category = cat,
                danger = items.count { it.status == Status.DANGER },
                warn = items.count { it.status == Status.WARN },
                total = items.size
            )
            items.forEach { rows += Row.Item(it, expanded.contains(it.id)) }
        }
        return rows
    }
}
