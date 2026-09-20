package com.detect.integrity.util

import java.io.File

/**
 * 轻量级 shell 执行器：全部走 sh -c，带超时保护，绝不抛异常。
 */
object Shell {

    data class Result(
        val exit: Int,
        val out: String,
        val err: String,
        val timedOut: Boolean
    ) {
        val ok: Boolean get() = exit == 0
        val text: String get() = (out + "\n" + err).trim()
    }

    fun exec(cmd: String, timeoutMs: Long = 2500): Result {
        return try {
            val proc = ProcessBuilder("sh", "-c", cmd)
                .redirectErrorStream(true)
                .start()
            val sb = StringBuilder()
            val reader = Thread {
                try {
                    proc.inputStream.bufferedReader().forEachLine { line ->
                        sb.append(line).append('\n')
                    }
                } catch (_: Exception) {
                }
            }
            reader.start()
            reader.join(timeoutMs)
            val timedOut = reader.isAlive
            if (timedOut) {
                runCatching { proc.destroy() }
            }
            val exit = try {
                proc.exitValue()
            } catch (_: IllegalThreadStateException) {
                -1
            }
            Result(exit, sb.toString().trim(), "", timedOut)
        } catch (e: Exception) {
            Result(-1, "", e.message ?: e.javaClass.simpleName, false)
        }
    }

    /** 只要输出文本，失败返回空串 */
    fun out(cmd: String, timeoutMs: Long = 2500): String = exec(cmd, timeoutMs).out

    /** 命令是否存在（command -v） */
    fun hasBinary(name: String): Boolean {
        val r = out("command -v $name 2>/dev/null")
        return r.isNotBlank()
    }

    /** 是否能拿到 root shell：执行 id 看 uid=0 */
    fun uidIsRoot(): Boolean {
        val r = exec("id", 1500).out
        return r.contains("uid=0")
    }
}
