package zako.zako.zako.zakoui.screen.moreSettings.state

import android.content.Context
import android.content.SharedPreferences
import android.content.res.Configuration
import android.net.Uri
import androidx.compose.runtime.Stable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableFloatStateOf
import androidx.compose.runtime.mutableIntStateOf
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.setValue
import com.sukisu.ultra.Natives
import com.sukisu.ultra.R
import com.sukisu.ultra.ui.theme.CardConfig
import com.sukisu.ultra.ui.theme.ThemeConfig
import java.util.Locale

/**
 * 更多设置状态管理
 */
@Stable
class MoreSettingsState(
    val context: Context,
    val prefs: SharedPreferences,
    val systemIsDark: Boolean
) {
    // 主题模式选择
    var themeMode by mutableIntStateOf(
        when (ThemeConfig.forceDarkMode) {
            true -> 2 // 深色
            false -> 1 // 浅色
            null -> 0 // 跟随系统
        }
    )

    // 动态颜色开关状态
    var useDynamicColor by mutableStateOf(ThemeConfig.useDynamicColor)

    // 对话框显示状态
    var showThemeModeDialog by mutableStateOf(false)
    var showLanguageDialog by mutableStateOf(false)
    var showThemeColorDialog by mutableStateOf(false)
    var showDpiConfirmDialog by mutableStateOf(false)
    var showImageEditor by mutableStateOf(false)

    // 动态管理器配置状态
    var dynamicSignConfig by mutableStateOf<Natives.DynamicManagerConfig?>(null)
    var isDynamicSignEnabled by mutableStateOf(false)
    var dynamicSignSize by mutableStateOf("")
    var dynamicSignHash by mutableStateOf("")
    var showDynamicSignDialog by mutableStateOf(false)

    // 获取当前语言设置
    var currentLanguage by mutableStateOf(prefs.getString("app_language", "") ?: "")

    // 各种设置开关状态
    var isSimpleMode by mutableStateOf(prefs.getBoolean("is_simple_mode", false))
    var isHideVersion by mutableStateOf(prefs.getBoolean("is_hide_version", false))
    var isHideOtherInfo by mutableStateOf(prefs.getBoolean("is_hide_other_info", false))
    var isShowKpmInfo by mutableStateOf(prefs.getBoolean("show_kpm_info", false))
    var isHideZygiskImplement by mutableStateOf(prefs.getBoolean("is_hide_zygisk_Implement", false))
    var isHideSusfsStatus by mutableStateOf(prefs.getBoolean("is_hide_susfs_status", false))
    var isHideLinkCard by mutableStateOf(prefs.getBoolean("is_hide_link_card", false))
    var isHideTagRow by mutableStateOf(prefs.getBoolean("is_hide_tag_row", false))
    var isKernelSimpleMode by mutableStateOf(prefs.getBoolean("is_kernel_simple_mode", false))
    var showMoreModuleInfo by mutableStateOf(prefs.getBoolean("show_more_module_info", false))
    var useAltIcon by mutableStateOf(prefs.getBoolean("use_alt_icon", false))

    // SELinux状态
    var selinuxEnabled by mutableStateOf(false)

    // SuSFS 状态
    var isSusFSEnabled by mutableStateOf(true)

    // 卡片配置状态
    var cardAlpha by mutableFloatStateOf(CardConfig.cardAlpha)
    var cardDim by mutableFloatStateOf(CardConfig.cardDim)
    var isCustomBackgroundEnabled by mutableStateOf(ThemeConfig.customBackgroundUri != null)

    // 图片选择状态
    var selectedImageUri by mutableStateOf<Uri?>(null)

    // DPI 设置
    val systemDpi = context.resources.displayMetrics.densityDpi
    var currentDpi by mutableIntStateOf(prefs.getInt("app_dpi", systemDpi))
    var tempDpi by mutableIntStateOf(currentDpi)
    var isDpiCustom by mutableStateOf(true)

    // 主题模式选项
    val themeOptions = listOf(
        context.getString(R.string.theme_follow_system),
        context.getString(R.string.theme_light),
        context.getString(R.string.theme_dark)
    )

    // 预设 DPI 选项
    val dpiPresets = mapOf(
        context.getString(R.string.dpi_size_small) to 240,
        context.getString(R.string.dpi_size_medium) to 320,
        context.getString(R.string.dpi_size_large) to 420,
        context.getString(R.string.dpi_size_extra_large) to 560
    )

    // 获取支持的语言列表
    val supportedLanguages by lazy {
        val languages = mutableListOf<Pair<String, String>>()
        languages.add("" to context.getString(R.string.language_follow_system))
        val locales = context.resources.configuration.locales
        for (i in 0 until locales.size()) {
            val locale = locales.get(i)
            val code = locale.toLanguageTag()
            if (!languages.any { it.first == code }) {
                languages.add(code to locale.getDisplayName(locale))
            }
        }

        val commonLocales = listOf(
            Locale.forLanguageTag("en"), // 英语
            Locale.forLanguageTag("zh-CN"), // 简体中文
            Locale.forLanguageTag("zh-HK"), // 繁体中文(香港)
            Locale.forLanguageTag("zh-TW"), // 繁体中文(台湾)
            Locale.forLanguageTag("ja"), // 日语
            Locale.forLanguageTag("fr"), // 法语
            Locale.forLanguageTag("de"), // 德语
            Locale.forLanguageTag("es"), // 西班牙语
            Locale.forLanguageTag("it"), // 意大利语
            Locale.forLanguageTag("ru"), // 俄语
            Locale.forLanguageTag("pt"), // 葡萄牙语
            Locale.forLanguageTag("ko"), // 韩语
            Locale.forLanguageTag("vi")  // 越南语
        )

        for (locale in commonLocales) {
            val code = locale.toLanguageTag()
            if (!languages.any { it.first == code }) {
                val config = Configuration(context.resources.configuration)
                config.setLocale(locale)
                try {
                    val testContext = context.createConfigurationContext(config)
                    testContext.getString(R.string.language_follow_system)
                    languages.add(code to locale.getDisplayName(locale))
                } catch (_: Exception) {
                }
            }
        }
        languages
    }
}