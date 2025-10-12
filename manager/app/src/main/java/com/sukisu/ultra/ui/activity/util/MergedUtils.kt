package com.sukisu.ultra.ui.activity.util

import android.annotation.SuppressLint
import android.content.Context
import android.content.Intent
import android.content.res.Configuration
import android.net.Uri
import android.os.Build
import androidx.compose.animation.*
import androidx.compose.runtime.Composable
import androidx.compose.runtime.mutableStateOf
import androidx.core.content.edit
import androidx.lifecycle.LifecycleCoroutineScope
import androidx.lifecycle.lifecycleScope
import com.ramcosta.composedestinations.generated.destinations.FlashScreenDestination
import com.ramcosta.composedestinations.generated.destinations.InstallScreenDestination
import com.ramcosta.composedestinations.navigation.DestinationsNavigator
import com.sukisu.ultra.Natives
import com.sukisu.ultra.ui.MainActivity
import com.sukisu.ultra.ui.component.ZipFileDetector
import com.sukisu.ultra.ui.component.ZipFileInfo
import com.sukisu.ultra.ui.component.ZipType
import com.sukisu.ultra.ui.screen.FlashIt
import com.sukisu.ultra.ui.util.*
import com.sukisu.ultra.ui.viewmodel.HomeViewModel
import com.sukisu.ultra.ui.viewmodel.SuperUserViewModel
import com.sukisu.ultra.ui.webui.initPlatform
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.delay
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.isActive
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import java.util.*

object AnimatedBottomBar {
    @Composable
    fun AnimatedBottomBarWrapper(
        showBottomBar: Boolean,
        content: @Composable () -> Unit
    ) {
        AnimatedVisibility(
            visible = showBottomBar,
            enter = slideInVertically(initialOffsetY = { it }) + fadeIn(),
            exit = slideOutVertically(targetOffsetY = { it }) + fadeOut()
        ) {
            content()
        }
    }
}

/**
 * 应用数据管理工具类
 */
object AppData {
    object DataRefreshManager {
        // 私有状态流
        private val _superuserCount = MutableStateFlow(0)
        private val _moduleCount = MutableStateFlow(0)
        private val _kpmModuleCount = MutableStateFlow(0)

        // 公开的只读状态流
        val superuserCount: StateFlow<Int> = _superuserCount.asStateFlow()
        val moduleCount: StateFlow<Int> = _moduleCount.asStateFlow()
        val kpmModuleCount: StateFlow<Int> = _kpmModuleCount.asStateFlow()

        /**
         * 刷新所有数据计数
         */
        fun refreshData() {
            _superuserCount.value = getSuperuserCountUse()
            _moduleCount.value = getModuleCountUse()
            _kpmModuleCount.value = getKpmModuleCountUse()
        }
    }

    /**
     * 获取超级用户应用计数
     */
    fun getSuperuserCountUse(): Int {
        return try {
            if (!rootAvailable()) return 0
            getSuperuserCount()
        } catch (_: Exception) {
            0
        }
    }

    /**
     * 获取模块计数
     */
    fun getModuleCountUse(): Int {
        return try {
            if (!rootAvailable()) return 0
            getModuleCount()
        } catch (_: Exception) {
            0
        }
    }

    /**
     * 获取KPM模块计数
     */
    fun getKpmModuleCountUse(): Int {
        return try {
            if (!rootAvailable()) return 0
            val kpmVersion = getKpmVersionUse()
            if (kpmVersion.isEmpty() || kpmVersion.startsWith("Error")) return 0
            getKpmModuleCount()
        } catch (_: Exception) {
            0
        }
    }

    /**
     * 获取KPM版本
     */
    fun getKpmVersionUse(): String {
        return try {
            if (!rootAvailable()) return ""
            val version = getKpmVersion()
            version.ifEmpty { "" }
        } catch (e: Exception) {
            "Error: ${e.message}"
        }
    }

    /**
     * 检查是否是完整功能模式
     */
    fun isFullFeatured(packageName: String): Boolean {
        val isManager = Natives.becomeManager(packageName)
        return isManager && !Natives.requireNewKernel() && rootAvailable()
    }
}

/**
 * ZIP文件处理工具类
 */
object ZipFileManager {
    val showConfirmationDialog = mutableStateOf(false)
    val pendingZipFiles = mutableStateOf<List<ZipFileInfo>>(emptyList())

    /**
     * 处理传入的ZIP文件URI
     */
    fun handleZipFiles(intent: Intent?): ArrayList<Uri>? {
        return when (intent?.action) {
            Intent.ACTION_SEND -> {
                val uri = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
                    intent.getParcelableExtra(Intent.EXTRA_STREAM, Uri::class.java)
                } else {
                    @Suppress("DEPRECATION")
                    intent.getParcelableExtra(Intent.EXTRA_STREAM)
                }
                uri?.let { arrayListOf(it) }
            }
            Intent.ACTION_SEND_MULTIPLE -> {
                if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
                    intent.getParcelableArrayListExtra(Intent.EXTRA_STREAM, Uri::class.java)
                } else {
                    @Suppress("DEPRECATION")
                    intent.getParcelableArrayListExtra(Intent.EXTRA_STREAM)
                }
            }
            else -> when {
                intent?.data != null -> arrayListOf(intent.data!!)
                Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU -> {
                    intent?.getParcelableArrayListExtra("uris", Uri::class.java)
                }
                else -> {
                    @Suppress("DEPRECATION")
                    (intent?.getParcelableArrayListExtra("uris"))
                }
            }
        }
    }

    /**
     * 检测ZIP文件类型并显示确认对话框
     */
    suspend fun detectZipTypeAndShowConfirmation(context: Context, zipUris: ArrayList<Uri>) {
        try {
            val zipFileInfos = ZipFileDetector.detectAndParseZipFiles(context, zipUris)

            withContext(Dispatchers.Main) {
                if (zipFileInfos.isNotEmpty()) {
                    pendingZipFiles.value = zipFileInfos
                    showConfirmationDialog.value = true
                } else {
                    (context as MainActivity).finish()
                }
            }
        } catch (e: Exception) {
            withContext(Dispatchers.Main) {
                (context as MainActivity).finish()
            }
            e.printStackTrace()
        }
    }

    /**
     * 导航到内核刷写界面
     */
    fun navigateToFlashScreen(
        context: Context,
        zipFiles: List<ZipFileInfo>,
        navigator: DestinationsNavigator,
        scope: LifecycleCoroutineScope
    ) {
        scope.launch {
            val moduleUris = zipFiles.filter { it.type == ZipType.MODULE }.map { it.uri }
            val kernelUris = zipFiles.filter { it.type == ZipType.KERNEL }.map { it.uri }

            when {
                // 内核文件
                kernelUris.isNotEmpty() && moduleUris.isEmpty() -> {
                    if (kernelUris.size == 1 && rootAvailable()) {
                        navigator.navigate(
                            InstallScreenDestination(
                                preselectedKernelUri = kernelUris.first().toString()
                            )
                        )
                    }
                    setAutoExitAfterFlash(context)
                }
                // 模块文件
                moduleUris.isNotEmpty() -> {
                    navigator.navigate(
                        FlashScreenDestination(
                            FlashIt.FlashModules(ArrayList(moduleUris))
                        )
                    )
                    setAutoExitAfterFlash(context)
                }
            }
        }
    }

    /**
     * 设置内核刷写后自动退出
     */
    private fun setAutoExitAfterFlash(context: Context) {
        val sharedPref = context.getSharedPreferences("kernel_flash_prefs", Context.MODE_PRIVATE)
        sharedPref.edit {
            putBoolean("auto_exit_after_flash", true)
        }
    }

    /**
     * 清理ZIP文件状态
     */
    fun clearZipFileState() {
        showConfirmationDialog.value = false
        pendingZipFiles.value = emptyList()
    }
}

/**
 * ViewModel管理工具类
 */
object ViewModelManager {
    lateinit var superUserViewModel: SuperUserViewModel
    lateinit var homeViewModel: HomeViewModel

    /**
     * 初始化ViewModel
     */
    fun initializeViewModels() {
        superUserViewModel = SuperUserViewModel()
        homeViewModel = HomeViewModel()
    }

    /**
     * 刷新ViewModel数据
     */
    suspend fun refreshViewModelData() {
        try {
            superUserViewModel.fetchAppList()
        } catch (e: Exception) {
            e.printStackTrace()
        }
    }
}

/**
 * 数据刷新工具类
 */
object DataRefreshUtils {

    fun startDataRefreshCoroutine(scope: LifecycleCoroutineScope) {
        scope.launch(Dispatchers.IO) {
            while (isActive) {
                AppData.DataRefreshManager.refreshData()
                delay(5000)
            }
        }
    }

    fun startSettingsMonitorCoroutine(
        scope: LifecycleCoroutineScope,
        activity: MainActivity,
        settingsStateFlow: MutableStateFlow<MainActivity.SettingsState>
    ) {
        scope.launch(Dispatchers.IO) {
            while (isActive) {
                val prefs = activity.getSharedPreferences("settings", Context.MODE_PRIVATE)
                settingsStateFlow.value = MainActivity.SettingsState(
                    isHideOtherInfo = prefs.getBoolean("is_hide_other_info", false),
                    showKpmInfo = prefs.getBoolean("show_kpm_info", false)
                )
                delay(1000)
            }
        }
    }

    fun refreshData(scope: LifecycleCoroutineScope) {
        scope.launch {
            AppData.DataRefreshManager.refreshData()
        }
    }
}

/**
 * Activity初始化工具类
 */
object ActivityInitializer {
    /**
     * 初始化Activity的所有组件
     */
    suspend fun initialize(activity: MainActivity, settingsStateFlow: MutableStateFlow<MainActivity.SettingsState>) {
        // 初始化ViewModel
        ViewModelManager.initializeViewModels()

        // 初始化数据
        initializeData(activity, settingsStateFlow)

        // 初始化平台
        initPlatform()
    }

    private suspend fun initializeData(activity: MainActivity, settingsStateFlow: MutableStateFlow<MainActivity.SettingsState>) {
        // 获取应用列表
        ViewModelManager.refreshViewModelData()

        // 启动数据刷新协程
        DataRefreshUtils.startDataRefreshCoroutine(activity.lifecycleScope)
        DataRefreshUtils.startSettingsMonitorCoroutine(activity.lifecycleScope, activity, settingsStateFlow)

        // 初始化主题相关设置
        ThemeUtils.initializeThemeSettings(activity, settingsStateFlow)

        // 安装管理器
        val isManager = Natives.becomeManager(activity.packageName)
        if (isManager) {
            install()
        }
    }
}

/**
 * 显示设置工具类
 */
object DisplayUtils {

    fun applyCustomDpi(context: Context) {
        val prefs = context.getSharedPreferences("settings", Context.MODE_PRIVATE)
        val customDpi = prefs.getInt("app_dpi", 0)

        if (customDpi > 0) {
            try {
                val resources = context.resources
                val metrics = resources.displayMetrics
                metrics.density = customDpi / 160f
                @Suppress("DEPRECATION")
                metrics.scaledDensity = customDpi / 160f
                metrics.densityDpi = customDpi
            } catch (e: Exception) {
                e.printStackTrace()
            }
        }
    }
}

/**
 * 语言本地化工具类
 */
object LocaleUtils {

    @SuppressLint("ObsoleteSdkInt")
    fun applyLanguageSetting(context: Context) {
        val prefs = context.getSharedPreferences("settings", Context.MODE_PRIVATE)
        val languageCode = prefs.getString("app_language", "") ?: ""

        if (languageCode.isNotEmpty()) {
            val locale = Locale.forLanguageTag(languageCode)
            Locale.setDefault(locale)

            val resources = context.resources
            val config = Configuration(resources.configuration)
            config.setLocale(locale)
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.N) {
                context.createConfigurationContext(config)
            } else {
                @Suppress("DEPRECATION")
                resources.updateConfiguration(config, resources.displayMetrics)
            }
        }
    }

    fun applyLocale(context: Context): Context {
        val prefs = context.getSharedPreferences("settings", Context.MODE_PRIVATE)
        val languageCode = prefs.getString("app_language", "") ?: ""

        var newContext = context
        if (languageCode.isNotEmpty()) {
            val locale = Locale.forLanguageTag(languageCode)
            Locale.setDefault(locale)

            val config = Configuration(context.resources.configuration)
            config.setLocale(locale)
            newContext = context.createConfigurationContext(config)
        }

        return newContext
    }
}