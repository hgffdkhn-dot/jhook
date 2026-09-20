package com.detect.integrity.util

import java.security.MessageDigest

object Hash {
    fun sha256(data: ByteArray): String {
        return try {
            val md = MessageDigest.getInstance("SHA-256")
            md.update(data)
            md.digest().joinToString("") { "%02x".format(it) }
        } catch (e: Exception) {
            ""
        }
    }

    fun sha256(text: String): String = sha256(text.toByteArray())

    /** 把 a1:b2:c3 形式的指纹统一成小写无冒号形式，便于比对 */
    fun normalize(fp: String): String = fp
        .replace(":", "")
        .replace(" ", "")
        .trim()
        .lowercase()
}
