package com.svega.crypto.ed25519

fun crypto_verify_32(x: ByteArray, y: ByteArray): Int {
    var diffs = 0
    for (i in 0 until 32) {
        diffs = diffs or (x[i].toInt().and(0xFF) xor y[i].toInt().and(0xFF))
    }
    return (1 and (diffs - 1 shr 8)) - 1
}