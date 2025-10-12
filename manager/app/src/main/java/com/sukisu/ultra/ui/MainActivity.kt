package com.sukisu.ultra.ui

import android.content.Context
import android.content.res.Configuration
import android.net.Uri
import android.os.Build
import android.os.Bundle
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.activity.enableEdgeToEdge
import androidx.compose.foundation.layout.*
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Modifier
import androidx.lifecycle.lifecycleScope
import androidx.navigation.compose.currentBackStackEntryAsState
import androidx.navigation.compose.rememberNavController
import com.ramcosta.composedestinations.DestinationsNavHost
import com.ramcosta.composedestinations.generated.NavGraphs
import com.ramcosta.composedestinations.spec.NavHostGraphSpec
import com.ramcosta.composedestinations.utils.rememberDestinationsNavigator
import com.sukisu.ultra.ui.activity.component.BottomBar
import com.sukisu.ultra.ui.activity.util.*
import com.sukisu.ultra.ui.component.InstallConfirmationDialog
import com.sukisu.ultra.ui.theme.KernelSUTheme
import com.sukisu.ultra.ui.util.LocalSnackbarHost
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.launch

class MainActivity : ComponentActivity() {

    internal val settingsStateFlow = MutableStateFlow(SettingsState())

    data class SettingsState(
        val isHideOtherInfo: Boolean = false,
        val showKpmInfo: Boolean = false
    )

    // 标记避免重复初始化
    private var isInitialized = false

    override fun attachBaseContext(newBase: Context) {
        val context = LocaleUtils.applyLocale(newBase)
        super.attachBaseContext(context)
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        try {
            // 应用主题配置
            ThemeUtils.applyFullThemeConfiguration(this)

            // Enable edge to edge
            enableEdgeToEdge()

            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) {
                window.isNavigationBarContrastEnforced = false
            }

            super.onCreate(savedInstanceState)

            // 使用标记控制初始化流程
            if (!isInitialized) {
                lifecycleScope.launch {
                    ActivityInitializer.initialize(this@MainActivity, settingsStateFlow)
                }
                ThemeUtils.registerThemeChangeObserver(this)
                isInitialized = true
            }

            setContent {
                KernelSUTheme {
                    MainScreenContent()
                }
            }
        } catch (e: Exception) {
            e.printStackTrace()
        }
    }

    @Composable
    private fun MainScreenContent() {
        val navController = rememberNavController()
        val snackBarHostState = remember { SnackbarHostState() }
        val currentDestination = navController.currentBackStackEntryAsState().value?.destination
        val navigator = navController.rememberDestinationsNavigator()

        // 处理ZIP文件
        var zipUri by remember { mutableStateOf<ArrayList<Uri>?>(null) }

        // 在 LaunchedEffect 中处理 ZIP 文件
        LaunchedEffect(Unit) {
            zipUri = ZipFileManager.handleZipFiles(intent)
        }

        InstallConfirmationDialog(
            show = ZipFileManager.showConfirmationDialog.value,
            zipFiles = ZipFileManager.pendingZipFiles.value,
            onConfirm = { confirmedFiles ->
                ZipFileManager.navigateToFlashScreen(
                    this@MainActivity,
                    confirmedFiles,
                    navigator,
                    lifecycleScope
                )
                ZipFileManager.clearZipFileState()
            },
            onDismiss = {
                ZipFileManager.clearZipFileState()
                finish()
            }
        )

        LaunchedEffect(zipUri) {
            zipUri?.let { uris ->
                ZipFileManager.detectZipTypeAndShowConfirmation(this@MainActivity, uris)
            }
        }

        val showBottomBar = NavigationUtils.shouldShowBottomBar(currentDestination?.route)

        CompositionLocalProvider(
            LocalSnackbarHost provides snackBarHostState
        ) {
            Scaffold(
                bottomBar = {
                    AnimatedBottomBar.AnimatedBottomBarWrapper(
                        showBottomBar = showBottomBar,
                        content = { BottomBar(navController) }
                    )
                },
                contentWindowInsets = WindowInsets(0, 0, 0, 0)
            ) { innerPadding ->
                DestinationsNavHost(
                    modifier = Modifier.padding(innerPadding),
                    navGraph = NavGraphs.root as NavHostGraphSpec,
                    navController = navController,
                    defaultTransitions = NavigationUtils.createNavHostAnimations()
                )
            }
        }
    }

    override fun onResume() {
        try {
            super.onResume()
            LocaleUtils.applyLanguageSetting(this)
            ThemeUtils.onActivityResume()

            // 仅在需要时刷新数据
            if (isInitialized) {
                refreshData()
            }
        } catch (e: Exception) {
            e.printStackTrace()
        }
    }

    private fun refreshData() {
        lifecycleScope.launch {
            ViewModelManager.refreshViewModelData()
            DataRefreshUtils.refreshData(lifecycleScope)
        }
    }

    override fun onPause() {
        try {
            super.onPause()
            ThemeUtils.onActivityPause(this)
        } catch (e: Exception) {
            e.printStackTrace()
        }
    }

    override fun onDestroy() {
        try {
            ThemeUtils.unregisterThemeChangeObserver(this)
            super.onDestroy()
        } catch (e: Exception) {
            e.printStackTrace()
        }
    }

    override fun onConfigurationChanged(newConfig: Configuration) {
        try {
            super.onConfigurationChanged(newConfig)
            LocaleUtils.applyLanguageSetting(this)
        } catch (e: Exception) {
            e.printStackTrace()
        }
    }
}