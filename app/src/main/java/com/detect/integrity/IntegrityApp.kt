package com.detect.integrity

import android.app.Application
import androidx.appcompat.app.AppCompatDelegate
import androidx.preference.PreferenceManager
import com.google.android.material.color.DynamicColors

class IntegrityApp : Application() {

    override fun onCreate() {
        super.onCreate()
        val prefs = PreferenceManager.getDefaultSharedPreferences(this)

        AppCompatDelegate.setDefaultNightMode(
            when (prefs.getString("pref_theme", "system")) {
                "light" -> AppCompatDelegate.MODE_NIGHT_NO
                "dark" -> AppCompatDelegate.MODE_NIGHT_YES
                else -> AppCompatDelegate.MODE_NIGHT_FOLLOW_SYSTEM
            }
        )

        if (prefs.getBoolean("pref_dynamic_color", true)) {
            DynamicColors.applyToActivitiesIfAvailable(this)
        }
    }
}
