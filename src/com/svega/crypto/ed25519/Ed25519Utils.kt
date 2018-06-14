package com.svega.crypto.ed25519

fun crypto_verify_32(x: ByteArray, y: ByteArray): Int {
    var diffs = 0
    for (count in 0 until 32) {
        diffs = diffs or ((x[count].toInt() and 0xFF) xor (y[count].toInt() and 0xFF))
    }
    return diffs
}