package com.detect.integrity.ui

import android.os.Bundle
import androidx.appcompat.app.AppCompatDelegate
import androidx.preference.Preference
import androidx.preference.PreferenceFragmentCompat
import androidx.preference.SwitchPreferenceCompat
import com.detect.integrity.R

class SettingsFragment : PreferenceFragmentCompat() {

    override fun onCreatePreferences(savedInstanceState: Bundle?, rootKey: String?) {
        setPreferencesFromResource(R.xml.preferences, rootKey)

        findPreference<Preference>("pref_version")?.summary = "1.0.0"

        findPreference<Preference>("pref_theme")?.setOnPreferenceChangeListener { _, value ->
            applyTheme(value as? String ?: "system")
            true
        }

        findPreference<SwitchPreferenceCompat>("pref_dynamic_color")
            ?.setOnPreferenceChangeListener { _, _ ->
                // 动态取色在 Application 启动时生效，切换后需要重启进程
                requireActivity().recreate()
                true
            }
    }

    private fun applyTheme(value: String) {
        val mode = when (value) {
            "light" -> AppCompatDelegate.MODE_NIGHT_NO
            "dark" -> AppCompatDelegate.MODE_NIGHT_YES
            else -> AppCompatDelegate.MODE_NIGHT_FOLLOW_SYSTEM
        }
        AppCompatDelegate.setDefaultNightMode(mode)
    }
}
