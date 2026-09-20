package com.detect.integrity.ui

import android.os.Bundle
import android.widget.Toast
import androidx.appcompat.app.AppCompatActivity
import androidx.fragment.app.Fragment
import com.detect.integrity.R
import com.detect.integrity.databinding.ActivityMainBinding

class MainActivity : AppCompatActivity() {

    private lateinit var binding: ActivityMainBinding

    private var home: HomeFragment? = null
    private var checks: ChecksFragment? = null
    private var settings: SettingsFragment? = null
    private var currentId: Int = R.id.nav_home

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        binding = ActivityMainBinding.inflate(layoutInflater)
        setContentView(binding.root)

        binding.topAppBar.setOnMenuItemClickListener { item ->
            when (item.itemId) {
                R.id.action_export -> {
                    val h = home
                    if (h != null && h.isAdded) {
                        h.exportReport()
                    } else {
                        Toast.makeText(this, "请先在“检测”页完成一次检测", Toast.LENGTH_SHORT).show()
                    }
                    true
                }
                else -> false
            }
        }

        binding.bottomNav.setOnItemSelectedListener { item ->
            show(item.itemId)
            true
        }

        currentId = savedInstanceState?.getInt(KEY_TAB, R.id.nav_home) ?: R.id.nav_home
        binding.bottomNav.selectedItemId = currentId
    }

    private fun show(itemId: Int) {
        currentId = itemId
        val f: Fragment = when (itemId) {
            R.id.nav_checks -> checks ?: ChecksFragment().also { checks = it }
            R.id.nav_settings -> settings ?: SettingsFragment().also { settings = it }
            else -> home ?: HomeFragment().also { home = it }
        }
        supportFragmentManager.beginTransaction()
            .replace(R.id.fragment_container, f)
            .commit()
        binding.topAppBar.setTitle(
            when (itemId) {
                R.id.nav_checks -> R.string.checks_title
                R.id.nav_settings -> R.string.tab_settings
                else -> R.string.app_name
            }
        )
        binding.topAppBar.menu.findItem(R.id.action_export)?.isVisible = itemId == R.id.nav_home
    }

    override fun onSaveInstanceState(outState: Bundle) {
        super.onSaveInstanceState(outState)
        outState.putInt(KEY_TAB, currentId)
    }

    private companion object {
        const val KEY_TAB = "tab"
    }
}
