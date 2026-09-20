package com.detect.integrity.ui

import android.view.LayoutInflater
import android.view.ViewGroup
import androidx.recyclerview.widget.RecyclerView
import com.detect.integrity.databinding.ItemCheckCatalogBinding
import com.detect.integrity.databinding.ItemHeaderBinding
import com.detect.integrity.model.Category
import com.detect.integrity.model.CheckSpec

sealed class CatalogRow {
    data class Header(val category: Category, val count: Int) : CatalogRow()
    data class Spec(val spec: CheckSpec) : CatalogRow()
}

class CatalogAdapter(
    rows: List<CatalogRow>,
    private val onClick: (CheckSpec) -> Unit
) : RecyclerView.Adapter<RecyclerView.ViewHolder>() {

    private val items = rows.toMutableList()

    override fun getItemViewType(position: Int): Int =
        if (items[position] is CatalogRow.Header) 0 else 1

    override fun onCreateViewHolder(parent: ViewGroup, viewType: Int): RecyclerView.ViewHolder {
        val inf = LayoutInflater.from(parent.context)
        return if (viewType == 0) {
            HeaderVH(ItemHeaderBinding.inflate(inf, parent, false))
        } else {
            SpecVH(ItemCheckCatalogBinding.inflate(inf, parent, false))
        }
    }

    override fun onBindViewHolder(holder: RecyclerView.ViewHolder, position: Int) {
        when (val row = items[position]) {
            is CatalogRow.Header -> (holder as HeaderVH).bind(row)
            is CatalogRow.Spec -> (holder as SpecVH).bind(row)
        }
    }

    override fun getItemCount(): Int = items.size

    private inner class HeaderVH(private val b: ItemHeaderBinding) : RecyclerView.ViewHolder(b.root) {
        fun bind(row: CatalogRow.Header) {
            b.headerTitle.text = row.category.title
            b.headerSub.text = "${row.category.desc} · ${row.count} 项"
        }
    }

    private inner class SpecVH(private val b: ItemCheckCatalogBinding) : RecyclerView.ViewHolder(b.root) {
        fun bind(row: CatalogRow.Spec) {
            b.catalogTitle.text = row.spec.title
            val tags = mutableListOf(row.spec.description)
            if (row.spec.slow) tags += "· 耗时项"
            if (row.spec.needsPlay) tags += "· 需 Play 服务"
            b.catalogDesc.text = tags.joinToString(" ")
            b.root.setOnClickListener { onClick(row.spec) }
        }
    }
}
