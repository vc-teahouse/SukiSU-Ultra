package com.sukisu.ultra.ui.util

import android.content.Context
import android.content.Intent
import android.net.Uri
import java.io.BufferedReader
import java.io.InputStreamReader
import java.nio.charset.StandardCharsets
import java.util.zip.ZipInputStream
import com.sukisu.ultra.R
import android.util.Log
import com.sukisu.ultra.Natives
import java.io.File
import java.io.FileOutputStream
import java.io.IOException

object ModuleUtils {
    private const val TAG = "ModuleUtils"

    fun extractModuleName(context: Context, uri: Uri): String {
        if (uri == Uri.EMPTY) {
            Log.e(TAG, "The supplied URI is empty")
            return context.getString(R.string.unknown_module)
        }

        return try {
            Log.d(TAG, "Start extracting module names from URIs: $uri")

            // 从URI路径中提取文件名
            val fileName = uri.lastPathSegment?.let { path ->
                val lastSlash = path.lastIndexOf('/')
                if (lastSlash != -1 && lastSlash < path.length - 1) {
                    path.substring(lastSlash + 1)
                } else {
                    path
                }
            }?.removeSuffix(".zip") ?: context.getString(R.string.unknown_module)

            val formattedFileName = fileName.replace(Regex("[^a-zA-Z0-9\\s\\-_.@()\\u4e00-\\u9fa5]"), "").trim()
            var moduleName = formattedFileName

            try {
                // 打开ZIP文件输入流
                val inputStream = context.contentResolver.openInputStream(uri)
                if (inputStream == null) {
                    Log.e(TAG, "Unable to get input stream from URI: $uri")
                    return formattedFileName
                }

                val zipInputStream = ZipInputStream(inputStream)
                var entry = zipInputStream.nextEntry

                // 遍历ZIP文件中的条目，查找module.prop文件
                while (entry != null) {
                    if (entry.name == "module.prop") {
                        val reader = BufferedReader(InputStreamReader(zipInputStream, StandardCharsets.UTF_8))
                        var line: String?
                        while (reader.readLine().also { line = it } != null) {
                            if (line?.startsWith("name=") == true) {
                                moduleName = line.substringAfter("=")
                                moduleName = moduleName.replace(Regex("[^a-zA-Z0-9\\s\\-_.@()\\u4e00-\\u9fa5]"), "").trim()
                                break
                            }
                        }
                        break
                    }
                    entry = zipInputStream.nextEntry
                }
                zipInputStream.close()
                Log.d(TAG, "Successfully extracted module name: $moduleName")
                moduleName
            } catch (e: IOException) {
                Log.e(TAG, "Error reading ZIP file: ${e.message}")
                formattedFileName
            }
        } catch (e: Exception) {
            Log.e(TAG, "Exception when extracting module name: ${e.message}")
            context.getString(R.string.unknown_module)
        }
    }

    // 验证URI是否有效并可访问
    fun isUriAccessible(context: Context, uri: Uri): Boolean {
        if (uri == Uri.EMPTY) return false

        return try {
            val inputStream = context.contentResolver.openInputStream(uri)
            inputStream?.close()
            inputStream != null
        } catch (e: Exception) {
            Log.e(TAG, "The URI is inaccessible: $uri, Error: ${e.message}")
            false
        }
    }

    // 获取URI的持久权限
    fun takePersistableUriPermission(context: Context, uri: Uri) {
        try {
            val flags = Intent.FLAG_GRANT_READ_URI_PERMISSION
            context.contentResolver.takePersistableUriPermission(uri, flags)
            Log.d(TAG, "Persistent permissions for URIs have been obtained: $uri")
        } catch (e: Exception) {
            Log.e(TAG, "Unable to get persistent permissions on URIs: $uri, Error: ${e.message}")
        }
    }

    fun extractModuleId(context: Context, uri: Uri): String? {
        if (uri == Uri.EMPTY) {
            return null
        }

        return try {

            val inputStream = context.contentResolver.openInputStream(uri)
            if (inputStream == null) {
                return null
            }

            val zipInputStream = ZipInputStream(inputStream)
            var entry = zipInputStream.nextEntry
            var moduleId: String? = null

            // 遍历ZIP文件中的条目，查找module.prop文件
            while (entry != null) {
                if (entry.name == "module.prop") {
                    val reader = BufferedReader(InputStreamReader(zipInputStream, StandardCharsets.UTF_8))
                    var line: String?
                    while (reader.readLine().also { line = it } != null) {
                        if (line?.startsWith("id=") == true) {
                            moduleId = line.substringAfter("=").trim()
                            break
                        }
                    }
                    break
                }
                entry = zipInputStream.nextEntry
            }
            zipInputStream.close()
            moduleId
        } catch (e: Exception) {
            Log.e(TAG, "提取模块ID时发生异常: ${e.message}", e)
            null
        }
    }
}

// 模块签名验证工具类
object ModuleSignatureUtils {
    private const val TAG = "ModuleSignatureUtils"

    fun verifyModuleSignature(context: Context, moduleUri: Uri): Boolean {
        return try {
            // 创建临时文件
            val tempFile = File(context.cacheDir, "temp_module_${System.currentTimeMillis()}.zip")

            // 复制URI内容到临时文件
            context.contentResolver.openInputStream(moduleUri)?.use { inputStream ->
                FileOutputStream(tempFile).use { outputStream ->
                    inputStream.copyTo(outputStream)
                }
            }

            // 调用native方法验证签名
            val isVerified = Natives.verifyModuleSignature(tempFile.absolutePath)

            // 清理临时文件
            tempFile.delete()

            Log.d(TAG, "Module signature verification result: $isVerified")
            isVerified
        } catch (e: Exception) {
            Log.e(TAG, "Error verifying module signature", e)
            false
        }
    }

}

// 验证模块签名
fun verifyModuleSignature(context: Context, moduleUri: Uri): Boolean {
    return ModuleSignatureUtils.verifyModuleSignature(context, moduleUri)
}

object ModuleOperationUtils {
    private const val TAG = "ModuleOperationUtils"

    fun handleModuleInstallSuccess(context: Context, moduleUri: Uri, isSignatureVerified: Boolean) {
        if (!isSignatureVerified) {
            Log.d(TAG, "模块签名未验证，跳过创建验证标志")
            return
        }

        try {
            // 从ZIP文件提取模块ID
            val moduleId = ModuleUtils.extractModuleId(context, moduleUri)
            if (moduleId == null) {
                Log.e(TAG, "无法提取模块ID，无法创建验证标志")
                return
            }

            // 创建验证标志文件
            val success = ModuleVerificationManager.createVerificationFlag(moduleId)
            if (success) {
                Log.d(TAG, "模块 $moduleId 验证标志创建成功")
            } else {
                Log.e(TAG, "模块 $moduleId 验证标志创建失败")
            }
        } catch (e: Exception) {
            Log.e(TAG, "处理模块安装成功时发生异常", e)
        }
    }

    fun handleModuleUninstall(moduleId: String) {
        try {
            val success = ModuleVerificationManager.removeVerificationFlag(moduleId)
            if (success) {
                Log.d(TAG, "模块 $moduleId 验证标志移除成功")
            } else {
                Log.d(TAG, "模块 $moduleId 验证标志移除失败或不存在")
            }
        } catch (e: Exception) {
            Log.e(TAG, "处理模块卸载时发生异常: $moduleId", e)
        }
    }
    fun handleModuleUpdate(context: Context, moduleUri: Uri, isSignatureVerified: Boolean) {
        try {
            val moduleId = ModuleUtils.extractModuleId(context, moduleUri)
            if (moduleId == null) {
                Log.e(TAG, "无法提取模块ID，无法处理验证标志")
                return
            }

            if (isSignatureVerified) {
                // 签名验证通过，创建或更新验证标志
                val success = ModuleVerificationManager.createVerificationFlag(moduleId)
                if (success) {
                    Log.d(TAG, "模块 $moduleId 更新后验证标志已更新")
                } else {
                    Log.e(TAG, "模块 $moduleId 更新后验证标志更新失败")
                }
            } else {
                // 签名验证失败，移除验证标志
                ModuleVerificationManager.removeVerificationFlag(moduleId)
                Log.d(TAG, "模块 $moduleId 更新后签名未验证，验证标志已移除")
            }
        } catch (e: Exception) {
            Log.e(TAG, "处理模块更新时发生异常", e)
        }
    }
}