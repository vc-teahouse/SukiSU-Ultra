package zako.zako.zako.zakoui.screen.moreSettings.component

import androidx.compose.foundation.*
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Check
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.ui.unit.dp
import com.sukisu.ultra.R
import com.sukisu.ultra.ui.theme.*
import zako.zako.zako.zakoui.screen.moreSettings.MoreSettingsHandlers
import zako.zako.zako.zakoui.screen.moreSettings.state.MoreSettingsState

@Composable
fun MoreSettingsDialogs(
    state: MoreSettingsState,
    handlers: MoreSettingsHandlers
) {
    // 主题模式选择对话框
    if (state.showThemeModeDialog) {
        SingleChoiceDialog(
            title = stringResource(R.string.theme_mode),
            options = state.themeOptions,
            selectedIndex = state.themeMode,
            onOptionSelected = { index ->
                handlers.handleThemeModeChange(index)
            },
            onDismiss = { state.showThemeModeDialog = false }
        )
    }

    // 语言切换对话框
    if (state.showLanguageDialog) {
        KeyValueChoiceDialog(
            title = stringResource(R.string.language_setting),
            options = state.supportedLanguages,
            selectedCode = state.currentLanguage,
            onOptionSelected = { code ->
                handlers.handleLanguageChange(code)
            },
            onDismiss = { state.showLanguageDialog = false }
        )
    }

    // DPI 设置确认对话框
    if (state.showDpiConfirmDialog) {
        ConfirmDialog(
            title = stringResource(R.string.dpi_confirm_title),
            message = stringResource(R.string.dpi_confirm_message, state.currentDpi, state.tempDpi),
            summaryText = stringResource(R.string.dpi_confirm_summary),
            confirmText = stringResource(R.string.confirm),
            dismissText = stringResource(R.string.cancel),
            onConfirm = { handlers.handleDpiApply() },
            onDismiss = {
                state.showDpiConfirmDialog = false
                state.tempDpi = state.currentDpi
            }
        )
    }

    // 主题色选择对话框
    if (state.showThemeColorDialog) {
        ThemeColorDialog(
            onColorSelected = { theme ->
                handlers.handleThemeColorChange(theme)
                state.showThemeColorDialog = false
            },
            onDismiss = { state.showThemeColorDialog = false }
        )
    }

    // 动态管理器配置对话框
    if (state.showDynamicSignDialog) {
        DynamicManagerDialog(
            state = state,
            onConfirm = { enabled, size, hash ->
                handlers.handleDynamicManagerConfig(enabled, size, hash)
                state.showDynamicSignDialog = false
            },
            onDismiss = { state.showDynamicSignDialog = false }
        )
    }
}

@Composable
fun SingleChoiceDialog(
    title: String,
    options: List<String>,
    selectedIndex: Int,
    onOptionSelected: (Int) -> Unit,
    onDismiss: () -> Unit
) {
    AlertDialog(
        onDismissRequest = onDismiss,
        title = { Text(title) },
        text = {
            Column(modifier = Modifier.verticalScroll(rememberScrollState())) {
                options.forEachIndexed { index, option ->
                    Row(
                        modifier = Modifier
                            .fillMaxWidth()
                            .clickable {
                                onOptionSelected(index)
                                onDismiss()
                            }
                            .padding(vertical = 12.dp),
                        verticalAlignment = Alignment.CenterVertically
                    ) {
                        RadioButton(
                            selected = selectedIndex == index,
                            onClick = null
                        )
                        Spacer(modifier = Modifier.width(8.dp))
                        Text(option)
                    }
                }
            }
        },
        confirmButton = {
            TextButton(onClick = onDismiss) {
                Text(stringResource(R.string.cancel))
            }
        }
    )
}

@Composable
fun ConfirmDialog(
    title: String,
    message: String,
    summaryText: String? = null,
    confirmText: String = stringResource(R.string.confirm),
    dismissText: String = stringResource(R.string.cancel),
    onConfirm: () -> Unit,
    onDismiss: () -> Unit
) {
    AlertDialog(
        onDismissRequest = onDismiss,
        title = { Text(title) },
        text = {
            Column {
                Text(message)
                if (summaryText != null) {
                    Spacer(modifier = Modifier.height(8.dp))
                    Text(
                        summaryText,
                        style = MaterialTheme.typography.bodySmall
                    )
                }
            }
        },
        confirmButton = {
            TextButton(onClick = onConfirm) {
                Text(confirmText)
            }
        },
        dismissButton = {
            TextButton(onClick = onDismiss) {
                Text(dismissText)
            }
        }
    )
}

@Composable
fun KeyValueChoiceDialog(
    title: String,
    options: List<Pair<String, String>>,
    selectedCode: String,
    onOptionSelected: (String) -> Unit,
    onDismiss: () -> Unit
) {
    AlertDialog(
        onDismissRequest = onDismiss,
        title = { Text(title) },
        text = {
            Column(modifier = Modifier.verticalScroll(rememberScrollState())) {
                options.forEach { (code, name) ->
                    Row(
                        modifier = Modifier
                            .fillMaxWidth()
                            .clickable {
                                onOptionSelected(code)
                                onDismiss()
                            }
                            .padding(vertical = 12.dp),
                        verticalAlignment = Alignment.CenterVertically
                    ) {
                        RadioButton(
                            selected = selectedCode == code,
                            onClick = null
                        )
                        Spacer(modifier = Modifier.width(8.dp))
                        Text(name)
                    }
                }
            }
        },
        confirmButton = {
            TextButton(onClick = onDismiss) {
                Text(stringResource(R.string.cancel))
            }
        }
    )
}

@Composable
fun ThemeColorDialog(
    onColorSelected: (ThemeColors) -> Unit,
    onDismiss: () -> Unit
) {
    val themeColorOptions = listOf(
        stringResource(R.string.color_default) to ThemeColors.Default,
        stringResource(R.string.color_green) to ThemeColors.Green,
        stringResource(R.string.color_purple) to ThemeColors.Purple,
        stringResource(R.string.color_orange) to ThemeColors.Orange,
        stringResource(R.string.color_pink) to ThemeColors.Pink,
        stringResource(R.string.color_gray) to ThemeColors.Gray,
        stringResource(R.string.color_yellow) to ThemeColors.Yellow
    )

    AlertDialog(
        onDismissRequest = onDismiss,
        title = { Text(stringResource(R.string.choose_theme_color)) },
        text = {
            Column {
                themeColorOptions.forEach { (name, theme) ->
                    Row(
                        modifier = Modifier
                            .fillMaxWidth()
                            .clickable { onColorSelected(theme) }
                            .padding(vertical = 12.dp),
                        verticalAlignment = Alignment.CenterVertically
                    ) {
                        val isDark = isSystemInDarkTheme()
                        Box(
                            modifier = Modifier.padding(end = 12.dp)
                        ) {
                            Row(verticalAlignment = Alignment.CenterVertically) {
                                ColorCircle(
                                    color = if (isDark) theme.primaryDark else theme.primaryLight,
                                    isSelected = false,
                                    modifier = Modifier.padding(horizontal = 2.dp)
                                )
                                ColorCircle(
                                    color = if (isDark) theme.secondaryDark else theme.secondaryLight,
                                    isSelected = false,
                                    modifier = Modifier.padding(horizontal = 2.dp)
                                )
                                ColorCircle(
                                    color = if (isDark) theme.tertiaryDark else theme.tertiaryLight,
                                    isSelected = false,
                                    modifier = Modifier.padding(horizontal = 2.dp)
                                )
                            }
                        }
                        Text(name)
                        Spacer(modifier = Modifier.weight(1f))
                        // 当前选中的主题显示选中标记
                        if (ThemeConfig.currentTheme::class == theme::class) {
                            Icon(
                                Icons.Default.Check,
                                contentDescription = null,
                                tint = MaterialTheme.colorScheme.primary
                            )
                        }
                    }
                }
            }
        },
        confirmButton = {
            Button(
                onClick = onDismiss
            ) {
                Text(stringResource(R.string.cancel))
            }
        }
    )
}

@Composable
fun DynamicManagerDialog(
    state: MoreSettingsState,
    onConfirm: (Boolean, String, String) -> Unit,
    onDismiss: () -> Unit
) {
    var localEnabled by remember { mutableStateOf(state.isDynamicSignEnabled) }
    var localSize by remember { mutableStateOf(state.dynamicSignSize) }
    var localHash by remember { mutableStateOf(state.dynamicSignHash) }

    fun parseDynamicSignSize(input: String): Int? {
        return try {
            when {
                input.startsWith("0x", true) -> input.substring(2).toInt(16)
                else -> input.toInt()
            }
        } catch (_: NumberFormatException) {
            null
        }
    }

    AlertDialog(
        onDismissRequest = onDismiss,
        title = { Text(stringResource(R.string.dynamic_manager_title)) },
        text = {
            Column(
                modifier = Modifier.verticalScroll(rememberScrollState())
            ) {
                // 启用开关
                Row(
                    modifier = Modifier
                        .fillMaxWidth()
                        .clickable { localEnabled = !localEnabled }
                        .padding(vertical = 8.dp),
                    verticalAlignment = Alignment.CenterVertically
                ) {
                    Switch(
                        checked = localEnabled,
                        onCheckedChange = { localEnabled = it }
                    )
                    Spacer(modifier = Modifier.width(12.dp))
                    Text(stringResource(R.string.enable_dynamic_manager))
                }

                Spacer(modifier = Modifier.height(16.dp))

                // 签名大小输入
                OutlinedTextField(
                    value = localSize,
                    onValueChange = { input ->
                        val isValid = when {
                            input.isEmpty() -> true
                            input.matches(Regex("^\\d+$")) -> true
                            input.matches(Regex("^0[xX][0-9a-fA-F]*$")) -> true
                            else -> false
                        }
                        if (isValid) {
                            localSize = input
                        }
                    },
                    label = { Text(stringResource(R.string.signature_size)) },
                    enabled = localEnabled,
                    modifier = Modifier.fillMaxWidth(),
                    singleLine = true,
                    keyboardOptions = KeyboardOptions(
                        keyboardType = KeyboardType.Text
                    )
                )

                Spacer(modifier = Modifier.height(12.dp))

                // 签名哈希输入
                OutlinedTextField(
                    value = localHash,
                    onValueChange = { hash ->
                        if (hash.all { it in '0'..'9' || it in 'a'..'f' || it in 'A'..'F' }) {
                            localHash = hash
                        }
                    },
                    label = { Text(stringResource(R.string.signature_hash)) },
                    enabled = localEnabled,
                    modifier = Modifier.fillMaxWidth(),
                    singleLine = true,
                    supportingText = {
                        Text(stringResource(R.string.hash_must_be_64_chars))
                    },
                    isError = localEnabled && localHash.isNotEmpty() && localHash.length != 64
                )
            }
        },
        confirmButton = {
            Button(
                onClick = { onConfirm(localEnabled, localSize, localHash) },
                enabled = if (localEnabled) {
                    parseDynamicSignSize(localSize)?.let { it > 0 } == true &&
                            localHash.length == 64
                } else true
            ) {
                Text(stringResource(R.string.confirm))
            }
        },
        dismissButton = {
            TextButton(onClick = onDismiss) {
                Text(stringResource(R.string.cancel))
            }
        }
    )
}