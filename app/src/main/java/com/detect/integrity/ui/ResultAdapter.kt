package com.detect.integrity.ui

import android.content.Context
import android.graphics.drawable.ColorDrawable
import android.view.LayoutInflater
import android.view.ViewGroup
import androidx.core.content.ContextCompat
import androidx.core.graphics.drawable.DrawableCompat
import androidx.core.view.isVisible
import androidx.recyclerview.widget.DiffUtil
import androidx.recyclerview.widget.ListAdapter
import androidx.recyclerview.widget.RecyclerView
import com.detect.integrity.databinding.ItemHeaderBinding
import com.detect.integrity.databinding.ItemResultBinding
import com.detect.integrity.databinding.ItemSummaryBinding
import com.detect.integrity.model.Category
import com.detect.integrity.model.CheckResult
import com.detect.integrity.model.Score
import com.detect.integrity.model.Status

/** 首页列表的三种行 */
sealed class Row {
    data class Summary(
        val score: Score?,
        val running: Boolean,
        val progressText: String?,
        val lastScan: String?
    ) : Row()

    data class Header(
        val category: Category,
        val danger: Int,
        val warn: Int,
        val total: Int
    ) : Row()

    data class Item(val result: CheckResult, val expanded: Boolean) : Row()
}

class ResultAdapter(
    private val onItemClick: (CheckResult) -> Unit,
    private val onScan: () -> Unit,
    private val onExport: () -> Unit,
    private val onCopy: () -> Unit
) : ListAdapter<Row, RecyclerView.ViewHolder>(DIFF) {

    companion object {
        private const val T_SUMMARY = 0
        private const val T_HEADER = 1
        private const val T_ITEM = 2

        private val DIFF = object : DiffUtil.ItemCallback<Row>() {
            override fun areItemsTheSame(old: Row, new: Row): Boolean = when {
                old is Row.Summary && new is Row.Summary -> true
                old is Row.Header && new is Row.Header -> old.category == new.category
                old is Row.Item && new is Row.Item -> old.result.id == new.result.id
                else -> false
            }

            override fun areContentsTheSame(old: Row, new: Row): Boolean = old == new
        }
    }

    override fun getItemViewType(position: Int): Int = when (getItem(position)) {
        is Row.Summary -> T_SUMMARY
        is Row.Header -> T_HEADER
        is Row.Item -> T_ITEM
    }

    override fun onCreateViewHolder(parent: ViewGroup, viewType: Int): RecyclerView.ViewHolder {
        val inflater = LayoutInflater.from(parent.context)
        return when (viewType) {
            T_SUMMARY -> SummaryVH(ItemSummaryBinding.inflate(inflater, parent, false))
            T_HEADER -> HeaderVH(ItemHeaderBinding.inflate(inflater, parent, false))
            else -> ItemVH(ItemResultBinding.inflate(inflater, parent, false))
        }
    }

    override fun onBindViewHolder(holder: RecyclerView.ViewHolder, position: Int) {
        when (val row = getItem(position)) {
            is Row.Summary -> (holder as SummaryVH).bind(row)
            is Row.Header -> (holder as HeaderVH).bind(row)
            is Row.Item -> (holder as ItemVH).bind(row)
        }
    }

    inner class SummaryVH(private val b: ItemSummaryBinding) : RecyclerView.ViewHolder(b.root) {
        fun bind(row: Row.Summary) {
            val ctx = b.root.context
            val s = row.score
            b.scoreText.text = if (s == null) "--" else s.trust.toString()
            val bg = DrawableCompat.wrap(b.scoreText.background ?: ColorDrawable()).mutate()
            DrawableCompat.setTint(bg, ContextCompat.getColor(ctx, scoreColor(s)))
            b.scoreText.background = bg
            b.verdictText.text = when {
                row.running -> ctx.getString(com.detect.integrity.R.string.home_scanning)
                s == null -> ctx.getString(com.detect.integrity.R.string.home_not_scanned)
                else -> s.verdict
            }
            b.countsText.text = if (s == null) "" else ctx.getString(
                com.detect.integrity.R.string.home_counts, s.pass, s.warn, s.danger
            )
            b.timeText.text = row.lastScan?.let {
                ctx.getString(com.detect.integrity.R.string.home_last_scan, it)
            } ?: ""
            b.progressText.isVisible = row.progressText != null
            b.progressText.text = row.progressText ?: ""
            b.btnScan.isEnabled = !row.running
            b.btnScan.text = if (row.running) ctx.getString(com.detect.integrity.R.string.home_scanning)
            else ctx.getString(com.detect.integrity.R.string.home_scan)
            b.btnExport.isEnabled = s != null
            b.btnCopy.isEnabled = s != null
            b.btnScan.setOnClickListener { onScan() }
            b.btnExport.setOnClickListener { onExport() }
            b.btnCopy.setOnClickListener { onCopy() }
        }

        private fun scoreColor(s: Score?): Int = when {
            s == null -> com.detect.integrity.R.color.status_info
            s.danger > 0 -> com.detect.integrity.R.color.status_danger
            s.warn > 0 -> com.detect.integrity.R.color.status_warn
            else -> com.detect.integrity.R.color.status_pass
        }
    }

    inner class HeaderVH(private val b: ItemHeaderBinding) : RecyclerView.ViewHolder(b.root) {
        fun bind(row: Row.Header) {
            b.headerTitle.text = row.category.title
            val extra = when {
                row.danger > 0 -> "风险 ${row.danger}"
                row.warn > 0 -> "可疑 ${row.warn}"
                else -> "正常"
            }
            b.headerSub.text = "${row.category.desc} · 共 ${row.total} 项 · $extra"
        }
    }

    inner class ItemVH(private val b: ItemResultBinding) : RecyclerView.ViewHolder(b.root) {
        fun bind(row: Row.Item) {
            val r = row.result
            b.resultTitle.text = r.title
            b.resultSummary.text = r.summary
            b.statusIcon.setImageResource(iconOf(r.status))
            b.resultEvidence.isVisible = row.expanded && r.evidence.isNotEmpty()
            b.resultEvidence.text = r.evidence.joinToString("\n")
            b.root.setOnClickListener { onItemClick(r) }
        }

        private fun iconOf(s: Status): Int = when (s) {
            Status.PASS -> com.detect.integrity.R.drawable.ic_status_pass
            Status.WARN -> com.detect.integrity.R.drawable.ic_status_warn
            Status.DANGER -> com.detect.integrity.R.drawable.ic_status_danger
            Status.ERROR -> com.detect.integrity.R.drawable.ic_status_error
            Status.SKIP -> com.detect.integrity.R.drawable.ic_status_skip
            Status.INFO -> com.detect.integrity.R.drawable.ic_status_info
        }
    }
}

fun Context.statusText(s: Status): String = when (s) {
    Status.PASS -> "正常"
    Status.INFO -> "提示"
    Status.WARN -> "可疑"
    Status.DANGER -> "风险"
    Status.ERROR -> "失败"
    Status.SKIP -> "跳过"
}
