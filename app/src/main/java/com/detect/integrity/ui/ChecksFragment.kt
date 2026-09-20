package com.detect.integrity.ui

import android.os.Bundle
import android.view.View
import androidx.fragment.app.Fragment
import androidx.lifecycle.lifecycleScope
import com.detect.integrity.databinding.FragmentChecksBinding
import com.detect.integrity.detection.CheckRegistry
import com.detect.integrity.detection.DetectionEngine
import com.detect.integrity.model.Category
import com.detect.integrity.model.CheckSpec
import com.google.android.material.dialog.MaterialAlertDialogBuilder
import kotlinx.coroutines.launch

class ChecksFragment : Fragment(com.detect.integrity.R.layout.fragment_checks) {

    private var _b: FragmentChecksBinding? = null
    private val b get() = _b!!

    override fun onViewCreated(view: View, savedInstanceState: Bundle?) {
        super.onViewCreated(view, savedInstanceState)
        _b = FragmentChecksBinding.bind(view)

        val specs = CheckRegistry.all(requireContext())
        val rows = mutableListOf<CatalogRow>()
        for (cat in Category.values()) {
            val items = specs.filter { it.category == cat }
            if (items.isEmpty()) continue
            rows += CatalogRow.Header(cat, items.size)
            items.forEach { rows += CatalogRow.Spec(it) }
        }
        b.recycler.adapter = CatalogAdapter(rows) { spec -> runSingle(spec) }
    }

    private fun runSingle(spec: CheckSpec) {
        b.progress.show()
        viewLifecycleOwner.lifecycleScope.launch {
            val r = DetectionEngine.runSingle(requireContext(), spec)
            b.progress.hide()
            if (_b == null) return@launch
            val body = buildString {
                append("状态：").append(statusText(requireContext(), r.status)).append("\n\n")
                append(r.summary).append("\n")
                if (r.evidence.isNotEmpty()) {
                    append("\n—— 详细信息 ——\n")
                    r.evidence.forEach { append("• ").append(it).append("\n") }
                }
                append("\n耗时 ").append(r.durationMs).append(" ms")
            }
            MaterialAlertDialogBuilder(requireContext())
                .setTitle(r.title)
                .setMessage(body)
                .setPositiveButton(com.detect.integrity.R.string.dialog_close, null)
                .show()
        }
    }

    override fun onDestroyView() {
        super.onDestroyView()
        _b = null
    }
}
