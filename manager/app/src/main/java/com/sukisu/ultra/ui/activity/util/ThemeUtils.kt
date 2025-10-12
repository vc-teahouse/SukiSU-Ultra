package com.sukisu.ultra.ui.activity.util

import android.content.Context
import android.database.ContentObserver
import android.os.Handler
import androidx.core.content.edit
import com.sukisu.ultra.ui.MainActivity
import com.sukisu.ultra.ui.theme.CardConfig
import com.sukisu.ultra.ui.theme.ThemeConfig
import kotlinx.coroutines.flow.MutableStateFlow

class ThemeChangeContentObserver(
    handler: Handler,
    private val onThemeChanged: () -> Unit
) : ContentObserver(handler) {
    override fun onChange(selfChange: Boolean) {
        super.onChange(selfChange)
        onThemeChanged()
    }
}

/**
 * 主题管理工具类
 */
object ThemeUtils {

    private var themeChangeObserver: ThemeChangeContentObserver? = null

    /**
     * 初始化主题设置
     */
    fun initializeThemeSettings(activity: MainActivity, settingsStateFlow: MutableStateFlow<MainActivity.SettingsState>) {
        val prefs = activity.getSharedPreferences("settings", Context.MODE_PRIVATE)
        val isFirstRun = prefs.getBoolean("is_first_run", true)

        settingsStateFlow.value = MainActivity.SettingsState(
            isHideOtherInfo = prefs.getBoolean("is_hide_other_info", false),
            showKpmInfo = prefs.getBoolean("show_kpm_info", false)
        )

        if (isFirstRun) {
            ThemeConfig.preventBackgroundRefresh = false
            activity.getSharedPreferences("theme_prefs", Context.MODE_PRIVATE).edit {
                putBoolean("prevent_background_refresh", false)
            }
            prefs.edit { putBoolean("is_first_run", false) }
        }

        // 加载保存的背景设置
        loadThemeMode()
        loadThemeColors()
        loadDynamicColorState()
        CardConfig.load(activity.applicationContext)
    }

    /**
     * 注册主题变化观察者
     */
    fun registerThemeChangeObserver(activity: MainActivity): ThemeChangeContentObserver {
        val contentObserver = ThemeChangeContentObserver(Handler(activity.mainLooper)) {
            activity.runOnUiThread {
                if (!ThemeConfig.preventBackgroundRefresh) {
                    ThemeConfig.backgroundImageLoaded = false
                    loadCustomBackground()
                }
            }
        }

        activity.contentResolver.registerContentObserver(
            android.provider.Settings.System.getUriFor("ui_night_mode"),
            false,
            contentObserver
        )

        themeChangeObserver = contentObserver
        return contentObserver
    }

    /**
     * 注销主题变化观察者
     */
    fun unregisterThemeChangeObserver(activity: MainActivity) {
        themeChangeObserver?.let { observer ->
            activity.contentResolver.unregisterContentObserver(observer)
        }
        themeChangeObserver = null
    }

    /**
     * Activity暂停时的主题处理
     */
    fun onActivityPause(activity: MainActivity) {
        CardConfig.save(activity.applicationContext)
        activity.getSharedPreferences("theme_prefs", Context.MODE_PRIVATE).edit {
            putBoolean("prevent_background_refresh", true)
        }
        ThemeConfig.preventBackgroundRefresh = true
    }

    /**
     * Activity恢复时的主题处理
     */
    fun onActivityResume() {
        if (!ThemeConfig.backgroundImageLoaded && !ThemeConfig.preventBackgroundRefresh) {
            loadCustomBackground()
        }
    }

    /**
     * 应用完整的主题配置到Activity
     */
    fun applyFullThemeConfiguration(activity: MainActivity) {
        // 确保应用正确的语言设置
        LocaleUtils.applyLanguageSetting(activity)

        // 应用自定义 DPI
        DisplayUtils.applyCustomDpi(activity)
    }

    private fun loadThemeMode() {
        // 主题模式加载逻辑
    }

    private fun loadThemeColors() {
        // 主题颜色加载逻辑
    }

    private fun loadDynamicColorState() {
        // 动态颜色状态加载逻辑
    }

    private fun loadCustomBackground() {
        // 自定义背景加载逻辑
    }
}