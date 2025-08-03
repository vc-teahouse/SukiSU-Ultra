package com.sukisu.ultra.ui.util

import android.util.Log

/**

 * @author ShirkNeko
 * @date 2025/8/3
 */
object ModuleVerificationManager {
    private const val TAG = "ModuleVerificationManager"
    private const val VERIFICATION_FLAGS_DIR = "/data/adb/ksu/verified_modules"

    /**
     * 为指定模块创建验证标志文件
     *
     * @param moduleId 模块文件夹名称
     * @return 是否成功创建标志文件
     */
    fun createVerificationFlag(moduleId: String): Boolean {
        return try {
            val shell = getRootShell()
            val flagFilePath = "$VERIFICATION_FLAGS_DIR/$moduleId"

            // 确保目录存在
            val createDirCommand = "mkdir -p '$VERIFICATION_FLAGS_DIR'"
            shell.newJob().add(createDirCommand).exec()

            // 创建验证标志文件，写入验证时间戳
            val timestamp = System.currentTimeMillis()
            val command = "echo '$timestamp' > '$flagFilePath'"

            val result = shell.newJob().add(command).exec()

            if (result.isSuccess) {
                Log.d(TAG, "验证标志文件创建成功: $flagFilePath")
                true
            } else {
                Log.e(TAG, "验证标志文件创建失败: $moduleId")
                false
            }
        } catch (e: Exception) {
            Log.e(TAG, "创建验证标志文件时发生异常: $moduleId", e)
            false
        }
    }

    fun removeVerificationFlag(moduleId: String): Boolean {
        return try {
            val shell = getRootShell()
            val flagFilePath = "$VERIFICATION_FLAGS_DIR/$moduleId"

            val command = "rm -f '$flagFilePath'"
            val result = shell.newJob().add(command).exec()

            if (result.isSuccess) {
                Log.d(TAG, "验证标志文件移除成功: $flagFilePath")
                true
            } else {
                Log.e(TAG, "验证标志文件移除失败: $moduleId")
                false
            }
        } catch (e: Exception) {
            Log.e(TAG, "移除验证标志文件时发生异常: $moduleId", e)
            false
        }
    }

    fun getVerificationTimestamp(moduleId: String): Long {
        return try {
            val shell = getRootShell()
            val flagFilePath = "$VERIFICATION_FLAGS_DIR/$moduleId"

            val command = "cat '$flagFilePath' 2>/dev/null || echo '0'"
            val result = shell.newJob().add(command).to(ArrayList(), null).exec()

            if (result.isSuccess && result.out.isNotEmpty()) {
                val timestampStr = result.out.firstOrNull()?.trim() ?: "0"
                timestampStr.toLongOrNull() ?: 0L
            } else {
                0L
            }
        } catch (e: Exception) {
            Log.e(TAG, "获取验证时间戳时发生异常: $moduleId", e)
            0L
        }
    }

    fun batchCheckVerificationStatus(moduleIds: List<String>): Map<String, Boolean> {
        if (moduleIds.isEmpty()) return emptyMap()

        return try {
            val shell = getRootShell()
            val result = mutableMapOf<String, Boolean>()

            // 确保目录存在
            val createDirCommand = "mkdir -p '$VERIFICATION_FLAGS_DIR'"
            shell.newJob().add(createDirCommand).exec()

            // 批量检查所有模块的验证标志文件
            val commands = moduleIds.map { moduleId ->
                "test -f '$VERIFICATION_FLAGS_DIR/$moduleId' && echo '$moduleId:true' || echo '$moduleId:false'"
            }

            val command = commands.joinToString(" && ")
            val shellResult = shell.newJob().add(command).to(ArrayList(), null).exec()

            if (shellResult.isSuccess) {
                shellResult.out.forEach { line ->
                    val parts = line.split(":")
                    if (parts.size == 2) {
                        val moduleId = parts[0]
                        val isVerified = parts[1] == "true"
                        result[moduleId] = isVerified
                    }
                }
            }

            Log.d(TAG, "批量验证检查完成，共检查 ${moduleIds.size} 个模块")
            result
        } catch (e: Exception) {
            Log.e(TAG, "批量检查验证状态时发生异常", e)
            // 返回默认值，所有模块都标记为未验证
            moduleIds.associateWith { false }
        }
    }
}