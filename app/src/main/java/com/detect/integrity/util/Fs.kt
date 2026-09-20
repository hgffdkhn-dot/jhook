package com.detect.integrity.util

import java.io.File

/**
 * 文件系统访问，全部吞掉异常（Android 上大量目录对普通应用不可读）。
 */
object Fs {

    fun exists(path: String): Boolean = try {
        File(path).exists()
    } catch (_: Exception) {
        false
    }

    fun isDir(path: String): Boolean = try {
        File(path).isDirectory
    } catch (_: Exception) {
        false
    }

    fun isFile(path: String): Boolean = try {
        File(path).isFile
    } catch (_: Exception) {
        false
    }

    fun canExec(path: String): Boolean = try {
        File(path).canExecute()
    } catch (_: Exception) {
        false
    }

    fun canRead(path: String): Boolean = try {
        File(path).canRead()
    } catch (_: Exception) {
        false
    }

    fun list(path: String): List<String> = try {
        File(path).list()?.toList() ?: emptyList()
    } catch (_: Exception) {
        emptyList()
    }

    fun readLines(path: String): List<String> = try {
        if (!isFile(path)) emptyList() else File(path).readLines()
    } catch (_: Exception) {
        emptyList()
    }

    fun readText(path: String): String = try {
        if (!isFile(path)) "" else File(path).readText()
    } catch (_: Exception) {
        ""
    }

    /** 该路径下是否存在名字包含任一关键字的文件（非递归） */
    fun findNames(path: String, keywords: List<String>): List<String> {
        if (!isDir(path)) return emptyList()
        val lower = keywords.map { it.lowercase() }
        return list(path).filter { name ->
            val n = name.lowercase()
            lower.any { n.contains(it) }
        }.map { if (path.endsWith("/")) path + it else "$path/$it" }
    }

    /** 目录是否可写（尝试创建临时文件后立即删除） */
    fun isWritable(dir: String): Boolean {
        return try {
            val f = File(dir, ".integrity_probe_${System.nanoTime()}")
            val created = f.createNewFile()
            if (created) f.delete()
            created
        } catch (_: Exception) {
            false
        }
    }

    /** 目录是否非空 */
    fun isNonEmptyDir(path: String): Boolean = isDir(path) && list(path).isNotEmpty()
}
