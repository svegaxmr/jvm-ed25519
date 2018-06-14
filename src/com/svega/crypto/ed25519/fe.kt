package com.svega.crypto.ed25519

import com.svega.crypto.common.CryptoOps.load_3
import com.svega.crypto.common.CryptoOps.load_4

/**
 * Contains all functions starting with fe_
 */

fun fe_0(h: IntArray) {
    h[0] = 0
    h[1] = 0
    h[2] = 0
    h[3] = 0
    h[4] = 0
    h[5] = 0
    h[6] = 0
    h[7] = 0
    h[8] = 0
    h[9] = 0
}

fun fe_1(h: IntArray) {
    h[0] = 1
    h[1] = 0
    h[2] = 0
    h[3] = 0
    h[4] = 0
    h[5] = 0
    h[6] = 0
    h[7] = 0
    h[8] = 0
    h[9] = 0
}

fun fe_add(h: IntArray, f: IntArray, g: IntArray) {
    h[0] = f[0] + g[0]
    h[1] = f[1] + g[1]
    h[2] = f[2] + g[2]
    h[3] = f[3] + g[3]
    h[4] = f[4] + g[4]
    h[5] = f[5] + g[5]
    h[6] = f[6] + g[6]
    h[7] = f[7] + g[7]
    h[8] = f[8] + g[8]
    h[9] = f[9] + g[9]
}

fun fe_cmov(f: IntArray, g: IntArray, b_: Int){
    var x0 = f[0] xor g[0]
    var x1 = f[1] xor g[1]
    var x2 = f[2] xor g[2]
    var x3 = f[3] xor g[3]
    var x4 = f[4] xor g[4]
    var x5 = f[5] xor g[5]
    var x6 = f[6] xor g[6]
    var x7 = f[7] xor g[7]
    var x8 = f[8] xor g[8]
    var x9 = f[9] xor g[9]
    val b = -b_
    x0 = x0 and b
    x1 = x1 and b
    x2 = x2 and b
    x3 = x3 and b
    x4  = x4 and b
    x5 = x5 and b
    x6 = x6 and b
    x7 = x7 and b
    x8 = x8 and b
    x9 = x9 and b
    f[0] = f[0] xor x0
    f[1] = f[1] xor x1
    f[2] = f[2] xor x2
    f[3] = f[3] xor x3
    f[4] = f[4] xor x4
    f[5] = f[5] xor x5
    f[6] = f[6] xor x6
    f[7] = f[7] xor x7
    f[8] = f[8] xor x8
    f[9] = f[9] xor x9
}

fun fe_copy(h: IntArray, f: IntArray) {
    h[0] = f[0]
    h[1] = f[1]
    h[2] = f[2]
    h[3] = f[3]
    h[4] = f[4]
    h[5] = f[5]
    h[6] = f[6]
    h[7] = f[7]
    h[8] = f[8]
    h[9] = f[9]
}

fun fe_cswap(f: IntArray, g: IntArray, b_: Int) {
    var x0 = f[0] xor g[0]
    var x1 = f[1] xor g[1]
    var x2 = f[2] xor g[2]
    var x3 = f[3] xor g[3]
    var x4 = f[4] xor g[4]
    var x5 = f[5] xor g[5]
    var x6 = f[6] xor g[6]
    var x7 = f[7] xor g[7]
    var x8 = f[8] xor g[8]
    var x9 = f[9] xor g[9]
    val b = -b_
    x0 = x0 and b
    x1 = x1 and b
    x2 = x2 and b
    x3 = x3 and b
    x4 = x4 and b
    x5 = x5 and b
    x6 = x6 and b
    x7 = x7 and b
    x8 = x8 and b
    x9 = x9 and b
    f[0] = f[0] xor x0
    f[1] = f[1] xor x1
    f[2] = f[2] xor x2
    f[3] = f[3] xor x3
    f[4] = f[4] xor x4
    f[5] = f[5] xor x5
    f[6] = f[6] xor x6
    f[7] = f[7] xor x7
    f[8] = f[8] xor x8
    f[9] = f[9] xor x9
    g[0] = g[0] xor x0
    g[1] = g[1] xor x1
    g[2] = g[2] xor x2
    g[3] = g[3] xor x3
    g[4] = g[4] xor x4
    g[5] = g[5] xor x5
    g[6] = g[6] xor x6
    g[7] = g[7] xor x7
    g[8] = g[8] xor x8
    g[9] = g[9] xor x9
}

fun fe_frombytes(h: IntArray, s: ByteArray) {
    var h0 = load_4(s, 0)
    var h1 = load_3(s, 4) shl 6
    var h2 = load_3(s, 7) shl 5
    var h3 = load_3(s, 10) shl 3
    var h4 = load_3(s, 13) shl 2
    var h5 = load_4(s, 16)
    var h6 = load_3(s, 20) shl 7
    var h7 = load_3(s, 23) shl 5
    var h8 = load_3(s, 26) shl 4
    var h9 = load_3(s, 29) and 8388607 shl 2
    val carry0: Long
    val carry1: Long
    val carry2: Long
    val carry3: Long
    val carry4: Long
    val carry5: Long
    val carry6: Long
    val carry7: Long
    val carry8: Long
    val carry9: Long

    carry9 = h9 + (1 shl 24).toLong() shr 25
    h0 += carry9 * 19
    h9 -= carry9 shl 25
    carry1 = h1 + (1 shl 24).toLong() shr 25
    h2 += carry1
    h1 -= carry1 shl 25
    carry3 = h3 + (1 shl 24).toLong() shr 25
    h4 += carry3
    h3 -= carry3 shl 25
    carry5 = h5 + (1 shl 24).toLong() shr 25
    h6 += carry5
    h5 -= carry5 shl 25
    carry7 = h7 + (1 shl 24).toLong() shr 25
    h8 += carry7
    h7 -= carry7 shl 25

    carry0 = h0 + (1 shl 25).toLong() shr 26
    h1 += carry0
    h0 -= carry0 shl 26
    carry2 = h2 + (1 shl 25).toLong() shr 26
    h3 += carry2
    h2 -= carry2 shl 26
    carry4 = h4 + (1 shl 25).toLong() shr 26
    h5 += carry4
    h4 -= carry4 shl 26
    carry6 = h6 + (1 shl 25).toLong() shr 26
    h7 += carry6
    h6 -= carry6 shl 26
    carry8 = h8 + (1 shl 25).toLong() shr 26
    h9 += carry8
    h8 -= carry8 shl 26

    h[0] = h0.toInt()
    h[1] = h1.toInt()
    h[2] = h2.toInt()
    h[3] = h3.toInt()
    h[4] = h4.toInt()
    h[5] = h5.toInt()
    h[6] = h6.toInt()
    h[7] = h7.toInt()
    h[8] = h8.toInt()
    h[9] = h9.toInt()
}

fun fe_invert(out: IntArray, z: IntArray) {
    val t0 = IntArray(10)
    val t1 = IntArray(10)
    val t2 = IntArray(10)
    val t3 = IntArray(10)
    var i = 1
    fe_sq(t0, z)
    while (i < 1) {
        fe_sq(t0, t0)
        ++i
    }
    fe_sq(t1, t0)
    i = 1
    while (i < 2) {
        fe_sq(t1, t1)
        ++i
    }
    fe_mul(t1, z, t1)
    fe_mul(t0, t0, t1)
    fe_sq(t2, t0)
    i = 1
    while (i < 1) {
        fe_sq(t2, t2)
        ++i
    }
    fe_mul(t1, t1, t2)
    fe_sq(t2, t1)
    i = 1
    while (i < 5) {
        fe_sq(t2, t2)
        ++i
    }
    fe_mul(t1, t2, t1)
    fe_sq(t2, t1)
    i = 1
    while (i < 10) {
        fe_sq(t2, t2)
        ++i
    }
    fe_mul(t2, t2, t1)
    fe_sq(t3, t2)
    i = 1
    while (i < 20) {
        fe_sq(t3, t3)
        ++i
    }
    fe_mul(t2, t3, t2)
    fe_sq(t2, t2)
    i = 1
    while (i < 10) {
        fe_sq(t2, t2)
        ++i
    }
    fe_mul(t1, t2, t1)
    fe_sq(t2, t1)
    i = 1
    while (i < 50) {
        fe_sq(t2, t2)
        ++i
    }
    fe_mul(t2, t2, t1)
    fe_sq(t3, t2)
    i = 1
    while (i < 100) {
        fe_sq(t3, t3)
        ++i
    }
    fe_mul(t2, t3, t2)
    fe_sq(t2, t2)
    i = 1
    while (i < 50) {
        fe_sq(t2, t2)
        ++i
    }
    fe_mul(t1, t2, t1)
    fe_sq(t1, t1)
    i = 1
    while (i < 5) {
        fe_sq(t1, t1)
        ++i
    }
    fe_mul(out, t1, t0)
}

fun fe_isnegative(f: IntArray): Int {
    val s = ByteArray(32)
    fe_tobytes(s, f)
    return s[0].toInt() and 1
}

val zero = ByteArray(32)

fun fe_isnonzero(f: IntArray): Int {
    val s = ByteArray(32)
    fe_tobytes(s, f)
    return crypto_verify_32(s, zero)
}

fun fe_mul1(f: IntArray, g: IntArray): LongArray {
    val f0 = f[0]
    val f1 = f[1]
    val f2 = f[2]
    val f3 = f[3]
    val f4 = f[4]
    val f5 = f[5]
    val f6 = f[6]
    val f7 = f[7]
    val f8 = f[8]
    val f9 = f[9]
    val g0 = g[0]
    val g1 = g[1]
    val g2 = g[2]
    val g3 = g[3]
    val g4 = g[4]
    val g5 = g[5]
    val g6 = g[6]
    val g7 = g[7]
    val g8 = g[8]
    val g9 = g[9]
    val g1_19 = 19 * g1 /* 1.959375*2^29 */
    val g2_19 = 19 * g2 /* 1.959375*2^30; still ok */
    val g3_19 = 19 * g3
    val g4_19 = 19 * g4
    val g5_19 = 19 * g5
    val g6_19 = 19 * g6
    val g7_19 = 19 * g7
    val g8_19 = 19 * g8
    val g9_19 = 19 * g9
    val f1_2 = 2 * f1
    val f3_2 = 2 * f3
    val f5_2 = 2 * f5
    val f7_2 = 2 * f7
    val f9_2 = 2 * f9
    val f0g0 = f0 * g0.toLong()
    val f0g1 = f0 * g1.toLong()
    val f0g2 = f0 * g2.toLong()
    val f0g3 = f0 * g3.toLong()
    val f0g4 = f0 * g4.toLong()
    val f0g5 = f0 * g5.toLong()
    val f0g6 = f0 * g6.toLong()
    val f0g7 = f0 * g7.toLong()
    val f0g8 = f0 * g8.toLong()
    val f0g9 = f0 * g9.toLong()
    val f1g0 = f1 * g0.toLong()
    val f1g1_2 = f1_2 * g1.toLong()
    val f1g2 = f1 * g2.toLong()
    val f1g3_2 = f1_2 * g3.toLong()
    val f1g4 = f1 * g4.toLong()
    val f1g5_2 = f1_2 * g5.toLong()
    val f1g6 = f1 * g6.toLong()
    val f1g7_2 = f1_2 * g7.toLong()
    val f1g8 = f1 * g8.toLong()
    val f1g9_38 = f1_2 * g9_19.toLong()
    val f2g0 = f2 * g0.toLong()
    val f2g1 = f2 * g1.toLong()
    val f2g2 = f2 * g2.toLong()
    val f2g3 = f2 * g3.toLong()
    val f2g4 = f2 * g4.toLong()
    val f2g5 = f2 * g5.toLong()
    val f2g6 = f2 * g6.toLong()
    val f2g7 = f2 * g7.toLong()
    val f2g8_19 = f2 * g8_19.toLong()
    val f2g9_19 = f2 * g9_19.toLong()
    val f3g0 = f3 * g0.toLong()
    val f3g1_2 = f3_2 * g1.toLong()
    val f3g2 = f3 * g2.toLong()
    val f3g3_2 = f3_2 * g3.toLong()
    val f3g4 = f3 * g4.toLong()
    val f3g5_2 = f3_2 * g5.toLong()
    val f3g6 = f3 * g6.toLong()
    val f3g7_38 = f3_2 * g7_19.toLong()
    val f3g8_19 = f3 * g8_19.toLong()
    val f3g9_38 = f3_2 * g9_19.toLong()
    val f4g0 = f4 * g0.toLong()
    val f4g1 = f4 * g1.toLong()
    val f4g2 = f4 * g2.toLong()
    val f4g3 = f4 * g3.toLong()
    val f4g4 = f4 * g4.toLong()
    val f4g5 = f4 * g5.toLong()
    val f4g6_19 = f4 * g6_19.toLong()
    val f4g7_19 = f4 * g7_19.toLong()
    val f4g8_19 = f4 * g8_19.toLong()
    val f4g9_19 = f4 * g9_19.toLong()
    val f5g0 = f5 * g0.toLong()
    val f5g1_2 = f5_2 * g1.toLong()
    val f5g2 = f5 * g2.toLong()
    val f5g3_2 = f5_2 * g3.toLong()
    val f5g4 = f5 * g4.toLong()
    val f5g5_38 = f5_2 * g5_19.toLong()
    val f5g6_19 = f5 * g6_19.toLong()
    val f5g7_38 = f5_2 * g7_19.toLong()
    val f5g8_19 = f5 * g8_19.toLong()
    val f5g9_38 = f5_2 * g9_19.toLong()
    val f6g0 = f6 * g0.toLong()
    val f6g1 = f6 * g1.toLong()
    val f6g2 = f6 * g2.toLong()
    val f6g3 = f6 * g3.toLong()
    val f6g4_19 = f6 * g4_19.toLong()
    val f6g5_19 = f6 * g5_19.toLong()
    val f6g6_19 = f6 * g6_19.toLong()
    val f6g7_19 = f6 * g7_19.toLong()
    val f6g8_19 = f6 * g8_19.toLong()
    val f6g9_19 = f6 * g9_19.toLong()
    val f7g0 = f7 * g0.toLong()
    val f7g1_2 = f7_2 * g1.toLong()
    val f7g2 = f7 * g2.toLong()
    val f7g3_38 = f7_2 * g3_19.toLong()
    val f7g4_19 = f7 * g4_19.toLong()
    val f7g5_38 = f7_2 * g5_19.toLong()
    val f7g6_19 = f7 * g6_19.toLong()
    val f7g7_38 = f7_2 * g7_19.toLong()
    val f7g8_19 = f7 * g8_19.toLong()
    val f7g9_38 = f7_2 * g9_19.toLong()
    val f8g0 = f8 * g0.toLong()
    val f8g1 = f8 * g1.toLong()
    val f8g2_19 = f8 * g2_19.toLong()
    val f8g3_19 = f8 * g3_19.toLong()
    val f8g4_19 = f8 * g4_19.toLong()
    val f8g5_19 = f8 * g5_19.toLong()
    val f8g6_19 = f8 * g6_19.toLong()
    val f8g7_19 = f8 * g7_19.toLong()
    val f8g8_19 = f8 * g8_19.toLong()
    val f8g9_19 = f8 * g9_19.toLong()
    val f9g0 = f9 * g0.toLong()
    val f9g1_38 = f9_2 * g1_19.toLong()
    val f9g2_19 = f9 * g2_19.toLong()
    val f9g3_38 = f9_2 * g3_19.toLong()
    val f9g4_19 = f9 * g4_19.toLong()
    val f9g5_38 = f9_2 * g5_19.toLong()
    val f9g6_19 = f9 * g6_19.toLong()
    val f9g7_38 = f9_2 * g7_19.toLong()
    val f9g8_19 = f9 * g8_19.toLong()
    val f9g9_38 = f9_2 * g9_19.toLong()

    val h = LongArray(10)
    h[0] = f0g0 + f1g9_38 + f2g8_19 + f3g7_38 + f4g6_19 + f5g5_38 + f6g4_19 + f7g3_38 + f8g2_19 + f9g1_38
    h[1] = f0g1 + f1g0 + f2g9_19 + f3g8_19 + f4g7_19 + f5g6_19 + f6g5_19 + f7g4_19 + f8g3_19 + f9g2_19
    h[2] = f0g2 + f1g1_2 + f2g0 + f3g9_38 + f4g8_19 + f5g7_38 + f6g6_19 + f7g5_38 + f8g4_19 + f9g3_38
    h[3] = f0g3 + f1g2 + f2g1 + f3g0 + f4g9_19 + f5g8_19 + f6g7_19 + f7g6_19 + f8g5_19 + f9g4_19
    h[4] = f0g4 + f1g3_2 + f2g2 + f3g1_2 + f4g0 + f5g9_38 + f6g8_19 + f7g7_38 + f8g6_19 + f9g5_38
    h[5] = f0g5 + f1g4 + f2g3 + f3g2 + f4g1 + f5g0 + f6g9_19 + f7g8_19 + f8g7_19 + f9g6_19
    h[6] = f0g6 + f1g5_2 + f2g4 + f3g3_2 + f4g2 + f5g1_2 + f6g0 + f7g9_38 + f8g8_19 + f9g7_38
    h[7] = f0g7 + f1g6 + f2g5 + f3g4 + f4g3 + f5g2 + f6g1 + f7g0 + f8g9_19 + f9g8_19
    h[8] = f0g8 + f1g7_2 + f2g6 + f3g5_2 + f4g4 + f5g3_2 + f6g2 + f7g1_2 + f8g0 + f9g9_38
    h[9] = f0g9 + f1g8 + f2g7 + f3g6 + f4g5 + f5g4 + f6g3 + f7g2 + f8g1 + f9g0

    return h
}

fun fe_mul(h: IntArray, f: IntArray, g: IntArray) {
    val hr = fe_mul1(f, g)
    var h0 = hr[0]
    var h1 = hr[1]
    var h2 = hr[2]
    var h3 = hr[3]
    var h4 = hr[4]
    var h5 = hr[5]
    var h6 = hr[6]
    var h7 = hr[7]
    var h8 = hr[8]
    var h9 = hr[9]

    var carry0: Long
    val carry1: Long
    val carry2: Long
    val carry3: Long
    var carry4: Long
    val carry5: Long
    val carry6: Long
    val carry7: Long
    val carry8: Long
    val carry9: Long

    carry0 = h0 + (1 shl 25).toLong() shr 26
    h1 += carry0
    h0 -= carry0 shl 26
    carry4 = h4 + (1 shl 25).toLong() shr 26
    h5 += carry4
    h4 -= carry4 shl 26

    carry1 = h1 + (1 shl 24).toLong() shr 25
    h2 += carry1
    h1 -= carry1 shl 25
    carry5 = h5 + (1 shl 24).toLong() shr 25
    h6 += carry5
    h5 -= carry5 shl 25

    carry2 = h2 + (1 shl 25).toLong() shr 26
    h3 += carry2
    h2 -= carry2 shl 26
    carry6 = h6 + (1 shl 25).toLong() shr 26
    h7 += carry6
    h6 -= carry6 shl 26

    carry3 = h3 + (1 shl 24).toLong() shr 25
    h4 += carry3
    h3 -= carry3 shl 25
    carry7 = h7 + (1 shl 24).toLong() shr 25
    h8 += carry7
    h7 -= carry7 shl 25

    carry4 = h4 + (1 shl 25).toLong() shr 26
    h5 += carry4
    h4 -= carry4 shl 26
    carry8 = h8 + (1 shl 25).toLong() shr 26
    h9 += carry8
    h8 -= carry8 shl 26

    carry9 = h9 + (1 shl 24).toLong() shr 25
    h0 += carry9 * 19
    h9 -= carry9 shl 25

    carry0 = h0 + (1 shl 25).toLong() shr 26
    h1 += carry0
    h0 -= carry0 shl 26

    h[0] = h0.toInt()
    h[1] = h1.toInt()
    h[2] = h2.toInt()
    h[3] = h3.toInt()
    h[4] = h4.toInt()
    h[5] = h5.toInt()
    h[6] = h6.toInt()
    h[7] = h7.toInt()
    h[8] = h8.toInt()
    h[9] = h9.toInt()
}

fun fe_mul121666(h: IntArray, f: IntArray) {
    val f0 = f[0]
    val f1 = f[1]
    val f2 = f[2]
    val f3 = f[3]
    val f4 = f[4]
    val f5 = f[5]
    val f6 = f[6]
    val f7 = f[7]
    val f8 = f[8]
    val f9 = f[9]
    var h0 = f0 * 121666.toLong()
    var h1 = f1 * 121666.toLong()
    var h2 = f2 * 121666.toLong()
    var h3 = f3 * 121666.toLong()
    var h4 = f4 * 121666.toLong()
    var h5 = f5 * 121666.toLong()
    var h6 = f6 * 121666.toLong()
    var h7 = f7 * 121666.toLong()
    var h8 = f8 * 121666.toLong()
    var h9 = f9 * 121666.toLong()
    val carry0: Long
    val carry1: Long
    val carry2: Long
    val carry3: Long
    val carry4: Long
    val carry5: Long
    val carry6: Long
    val carry7: Long
    val carry8: Long
    val carry9: Long

    carry9 = h9 + (1 shl 24).toLong() shr 25
    h0 += carry9 * 19
    h9 -= carry9 shl 25
    carry1 = h1 + (1 shl 24).toLong() shr 25
    h2 += carry1
    h1 -= carry1 shl 25
    carry3 = h3 + (1 shl 24).toLong() shr 25
    h4 += carry3
    h3 -= carry3 shl 25
    carry5 = h5 + (1 shl 24).toLong() shr 25
    h6 += carry5
    h5 -= carry5 shl 25
    carry7 = h7 + (1 shl 24).toLong() shr 25
    h8 += carry7
    h7 -= carry7 shl 25

    carry0 = h0 + (1 shl 25).toLong() shr 26
    h1 += carry0
    h0 -= carry0 shl 26
    carry2 = h2 + (1 shl 25).toLong() shr 26
    h3 += carry2
    h2 -= carry2 shl 26
    carry4 = h4 + (1 shl 25).toLong() shr 26
    h5 += carry4
    h4 -= carry4 shl 26
    carry6 = h6 + (1 shl 25).toLong() shr 26
    h7 += carry6
    h6 -= carry6 shl 26
    carry8 = h8 + (1 shl 25).toLong() shr 26
    h9 += carry8
    h8 -= carry8 shl 26

    h[0] = h0.toInt()
    h[1] = h1.toInt()
    h[2] = h2.toInt()
    h[3] = h3.toInt()
    h[4] = h4.toInt()
    h[5] = h5.toInt()
    h[6] = h6.toInt()
    h[7] = h7.toInt()
    h[8] = h8.toInt()
    h[9] = h9.toInt()
}

fun fe_neg(h: IntArray, f: IntArray) {
    h[0] = -f[0]
    h[1] = -f[1]
    h[2] = -f[2]
    h[3] = -f[3]
    h[4] = -f[4]
    h[5] = -f[5]
    h[6] = -f[6]
    h[7] = -f[7]
    h[8] = -f[8]
    h[9] = -f[9]
}

fun fe_pow22523(out: IntArray, z: IntArray) {
    val t0 = IntArray(10)
    val t1 = IntArray(10)
    val t2 = IntArray(10)
    var i = 1
    fe_sq(t0, z)
    while (i < 1) {
        fe_sq(t0, t0)
        ++i
    }
    fe_sq(t1, t0)
    i = 1
    while (i < 2) {
        fe_sq(t1, t1)
        ++i
    }
    fe_mul(t1, z, t1)
    fe_mul(t0, t0, t1)
    fe_sq(t0, t0)
    i = 1
    while (i < 1) {
        fe_sq(t0, t0)
        ++i
    }
    fe_mul(t0, t1, t0)
    fe_sq(t1, t0)
    i = 1
    while (i < 5) {
        fe_sq(t1, t1)
        ++i
    }
    fe_mul(t0, t1, t0)
    fe_sq(t1, t0)
    i = 1
    while (i < 10) {
        fe_sq(t1, t1)
        ++i
    }
    fe_mul(t1, t1, t0)
    fe_sq(t2, t1)
    i = 1
    while (i < 20) {
        fe_sq(t2, t2)
        ++i
    }
    fe_mul(t1, t2, t1)
    fe_sq(t1, t1)
    i = 1
    while (i < 10) {
        fe_sq(t1, t1)
        ++i
    }
    fe_mul(t0, t1, t0)
    fe_sq(t1, t0)
    i = 1
    while (i < 50) {
        fe_sq(t1, t1)
        ++i
    }
    fe_mul(t1, t1, t0)
    fe_sq(t2, t1)
    i = 1
    while (i < 100) {
        fe_sq(t2, t2)
        ++i
    }
    fe_mul(t1, t2, t1)
    fe_sq(t1, t1)
    i = 1
    while (i < 50) {
        fe_sq(t1, t1)
        ++i
    }
    fe_mul(t0, t1, t0)
    fe_sq(t0, t0)
    i = 1
    while (i < 2) {
        fe_sq(t0, t0)
        ++i
    }
    fe_mul(out, t0, z)
}

fun fe_sq(h: IntArray, f: IntArray) {
    val f0 = f[0]
    val f1 = f[1]
    val f2 = f[2]
    val f3 = f[3]
    val f4 = f[4]
    val f5 = f[5]
    val f6 = f[6]
    val f7 = f[7]
    val f8 = f[8]
    val f9 = f[9]
    val f0_2 = 2 * f0
    val f1_2 = 2 * f1
    val f2_2 = 2 * f2
    val f3_2 = 2 * f3
    val f4_2 = 2 * f4
    val f5_2 = 2 * f5
    val f6_2 = 2 * f6
    val f7_2 = 2 * f7
    val f5_38 = 38 * f5 /* 1.959375*2^30 */
    val f6_19 = 19 * f6 /* 1.959375*2^30 */
    val f7_38 = 38 * f7 /* 1.959375*2^30 */
    val f8_19 = 19 * f8 /* 1.959375*2^30 */
    val f9_38 = 38 * f9 /* 1.959375*2^30 */
    val f0f0 = f0 * f0.toLong()
    val f0f1_2 = f0_2 * f1.toLong()
    val f0f2_2 = f0_2 * f2.toLong()
    val f0f3_2 = f0_2 * f3.toLong()
    val f0f4_2 = f0_2 * f4.toLong()
    val f0f5_2 = f0_2 * f5.toLong()
    val f0f6_2 = f0_2 * f6.toLong()
    val f0f7_2 = f0_2 * f7.toLong()
    val f0f8_2 = f0_2 * f8.toLong()
    val f0f9_2 = f0_2 * f9.toLong()
    val f1f1_2 = f1_2 * f1.toLong()
    val f1f2_2 = f1_2 * f2.toLong()
    val f1f3_4 = f1_2 * f3_2.toLong()
    val f1f4_2 = f1_2 * f4.toLong()
    val f1f5_4 = f1_2 * f5_2.toLong()
    val f1f6_2 = f1_2 * f6.toLong()
    val f1f7_4 = f1_2 * f7_2.toLong()
    val f1f8_2 = f1_2 * f8.toLong()
    val f1f9_76 = f1_2 * f9_38.toLong()
    val f2f2 = f2 * f2.toLong()
    val f2f3_2 = f2_2 * f3.toLong()
    val f2f4_2 = f2_2 * f4.toLong()
    val f2f5_2 = f2_2 * f5.toLong()
    val f2f6_2 = f2_2 * f6.toLong()
    val f2f7_2 = f2_2 * f7.toLong()
    val f2f8_38 = f2_2 * f8_19.toLong()
    val f2f9_38 = f2 * f9_38.toLong()
    val f3f3_2 = f3_2 * f3.toLong()
    val f3f4_2 = f3_2 * f4.toLong()
    val f3f5_4 = f3_2 * f5_2.toLong()
    val f3f6_2 = f3_2 * f6.toLong()
    val f3f7_76 = f3_2 * f7_38.toLong()
    val f3f8_38 = f3_2 * f8_19.toLong()
    val f3f9_76 = f3_2 * f9_38.toLong()
    val f4f4 = f4 * f4.toLong()
    val f4f5_2 = f4_2 * f5.toLong()
    val f4f6_38 = f4_2 * f6_19.toLong()
    val f4f7_38 = f4 * f7_38.toLong()
    val f4f8_38 = f4_2 * f8_19.toLong()
    val f4f9_38 = f4 * f9_38.toLong()
    val f5f5_38 = f5 * f5_38.toLong()
    val f5f6_38 = f5_2 * f6_19.toLong()
    val f5f7_76 = f5_2 * f7_38.toLong()
    val f5f8_38 = f5_2 * f8_19.toLong()
    val f5f9_76 = f5_2 * f9_38.toLong()
    val f6f6_19 = f6 * f6_19.toLong()
    val f6f7_38 = f6 * f7_38.toLong()
    val f6f8_38 = f6_2 * f8_19.toLong()
    val f6f9_38 = f6 * f9_38.toLong()
    val f7f7_38 = f7 * f7_38.toLong()
    val f7f8_38 = f7_2 * f8_19.toLong()
    val f7f9_76 = f7_2 * f9_38.toLong()
    val f8f8_19 = f8 * f8_19.toLong()
    val f8f9_38 = f8 * f9_38.toLong()
    val f9f9_38 = f9 * f9_38.toLong()
    var h0 = f0f0 + f1f9_76 + f2f8_38 + f3f7_76 + f4f6_38 + f5f5_38
    var h1 = f0f1_2 + f2f9_38 + f3f8_38 + f4f7_38 + f5f6_38
    var h2 = f0f2_2 + f1f1_2 + f3f9_76 + f4f8_38 + f5f7_76 + f6f6_19
    var h3 = f0f3_2 + f1f2_2 + f4f9_38 + f5f8_38 + f6f7_38
    var h4 = f0f4_2 + f1f3_4 + f2f2 + f5f9_76 + f6f8_38 + f7f7_38
    var h5 = f0f5_2 + f1f4_2 + f2f3_2 + f6f9_38 + f7f8_38
    var h6 = f0f6_2 + f1f5_4 + f2f4_2 + f3f3_2 + f7f9_76 + f8f8_19
    var h7 = f0f7_2 + f1f6_2 + f2f5_2 + f3f4_2 + f8f9_38
    var h8 = f0f8_2 + f1f7_4 + f2f6_2 + f3f5_4 + f4f4 + f9f9_38
    var h9 = f0f9_2 + f1f8_2 + f2f7_2 + f3f6_2 + f4f5_2
    var carry0: Long
    val carry1: Long
    val carry2: Long
    val carry3: Long
    var carry4: Long
    val carry5: Long
    val carry6: Long
    val carry7: Long
    val carry8: Long
    val carry9: Long

    carry0 = h0 + (1 shl 25).toLong() shr 26
    h1 += carry0
    h0 -= carry0 shl 26
    carry4 = h4 + (1 shl 25).toLong() shr 26
    h5 += carry4
    h4 -= carry4 shl 26

    carry1 = h1 + (1 shl 24).toLong() shr 25
    h2 += carry1
    h1 -= carry1 shl 25
    carry5 = h5 + (1 shl 24).toLong() shr 25
    h6 += carry5
    h5 -= carry5 shl 25

    carry2 = h2 + (1 shl 25).toLong() shr 26
    h3 += carry2
    h2 -= carry2 shl 26
    carry6 = h6 + (1 shl 25).toLong() shr 26
    h7 += carry6
    h6 -= carry6 shl 26

    carry3 = h3 + (1 shl 24).toLong() shr 25
    h4 += carry3
    h3 -= carry3 shl 25
    carry7 = h7 + (1 shl 24).toLong() shr 25
    h8 += carry7
    h7 -= carry7 shl 25

    carry4 = h4 + (1 shl 25).toLong() shr 26
    h5 += carry4
    h4 -= carry4 shl 26
    carry8 = h8 + (1 shl 25).toLong() shr 26
    h9 += carry8
    h8 -= carry8 shl 26

    carry9 = h9 + (1 shl 24).toLong() shr 25
    h0 += carry9 * 19
    h9 -= carry9 shl 25

    carry0 = h0 + (1 shl 25).toLong() shr 26
    h1 += carry0
    h0 -= carry0 shl 26

    h[0] = h0.toInt()
    h[1] = h1.toInt()
    h[2] = h2.toInt()
    h[3] = h3.toInt()
    h[4] = h4.toInt()
    h[5] = h5.toInt()
    h[6] = h6.toInt()
    h[7] = h7.toInt()
    h[8] = h8.toInt()
    h[9] = h9.toInt()
}

fun fe_sq2(h: IntArray, f: IntArray) {
    val f0 = f[0]
    val f1 = f[1]
    val f2 = f[2]
    val f3 = f[3]
    val f4 = f[4]
    val f5 = f[5]
    val f6 = f[6]
    val f7 = f[7]
    val f8 = f[8]
    val f9 = f[9]
    val f0_2 = 2 * f0
    val f1_2 = 2 * f1
    val f2_2 = 2 * f2
    val f3_2 = 2 * f3
    val f4_2 = 2 * f4
    val f5_2 = 2 * f5
    val f6_2 = 2 * f6
    val f7_2 = 2 * f7
    val f5_38 = 38 * f5 /* 1.959375*2^30 */
    val f6_19 = 19 * f6 /* 1.959375*2^30 */
    val f7_38 = 38 * f7 /* 1.959375*2^30 */
    val f8_19 = 19 * f8 /* 1.959375*2^30 */
    val f9_38 = 38 * f9 /* 1.959375*2^30 */
    val f0f0 = f0 * f0.toLong()
    val f0f1_2 = f0_2 * f1.toLong()
    val f0f2_2 = f0_2 * f2.toLong()
    val f0f3_2 = f0_2 * f3.toLong()
    val f0f4_2 = f0_2 * f4.toLong()
    val f0f5_2 = f0_2 * f5.toLong()
    val f0f6_2 = f0_2 * f6.toLong()
    val f0f7_2 = f0_2 * f7.toLong()
    val f0f8_2 = f0_2 * f8.toLong()
    val f0f9_2 = f0_2 * f9.toLong()
    val f1f1_2 = f1_2 * f1.toLong()
    val f1f2_2 = f1_2 * f2.toLong()
    val f1f3_4 = f1_2 * f3_2.toLong()
    val f1f4_2 = f1_2 * f4.toLong()
    val f1f5_4 = f1_2 * f5_2.toLong()
    val f1f6_2 = f1_2 * f6.toLong()
    val f1f7_4 = f1_2 * f7_2.toLong()
    val f1f8_2 = f1_2 * f8.toLong()
    val f1f9_76 = f1_2 * f9_38.toLong()
    val f2f2 = f2 * f2.toLong()
    val f2f3_2 = f2_2 * f3.toLong()
    val f2f4_2 = f2_2 * f4.toLong()
    val f2f5_2 = f2_2 * f5.toLong()
    val f2f6_2 = f2_2 * f6.toLong()
    val f2f7_2 = f2_2 * f7.toLong()
    val f2f8_38 = f2_2 * f8_19.toLong()
    val f2f9_38 = f2 * f9_38.toLong()
    val f3f3_2 = f3_2 * f3.toLong()
    val f3f4_2 = f3_2 * f4.toLong()
    val f3f5_4 = f3_2 * f5_2.toLong()
    val f3f6_2 = f3_2 * f6.toLong()
    val f3f7_76 = f3_2 * f7_38.toLong()
    val f3f8_38 = f3_2 * f8_19.toLong()
    val f3f9_76 = f3_2 * f9_38.toLong()
    val f4f4 = f4 * f4.toLong()
    val f4f5_2 = f4_2 * f5.toLong()
    val f4f6_38 = f4_2 * f6_19.toLong()
    val f4f7_38 = f4 * f7_38.toLong()
    val f4f8_38 = f4_2 * f8_19.toLong()
    val f4f9_38 = f4 * f9_38.toLong()
    val f5f5_38 = f5 * f5_38.toLong()
    val f5f6_38 = f5_2 * f6_19.toLong()
    val f5f7_76 = f5_2 * f7_38.toLong()
    val f5f8_38 = f5_2 * f8_19.toLong()
    val f5f9_76 = f5_2 * f9_38.toLong()
    val f6f6_19 = f6 * f6_19.toLong()
    val f6f7_38 = f6 * f7_38.toLong()
    val f6f8_38 = f6_2 * f8_19.toLong()
    val f6f9_38 = f6 * f9_38.toLong()
    val f7f7_38 = f7 * f7_38.toLong()
    val f7f8_38 = f7_2 * f8_19.toLong()
    val f7f9_76 = f7_2 * f9_38.toLong()
    val f8f8_19 = f8 * f8_19.toLong()
    val f8f9_38 = f8 * f9_38.toLong()
    val f9f9_38 = f9 * f9_38.toLong()
    var h0 = f0f0 + f1f9_76 + f2f8_38 + f3f7_76 + f4f6_38 + f5f5_38
    var h1 = f0f1_2 + f2f9_38 + f3f8_38 + f4f7_38 + f5f6_38
    var h2 = f0f2_2 + f1f1_2 + f3f9_76 + f4f8_38 + f5f7_76 + f6f6_19
    var h3 = f0f3_2 + f1f2_2 + f4f9_38 + f5f8_38 + f6f7_38
    var h4 = f0f4_2 + f1f3_4 + f2f2 + f5f9_76 + f6f8_38 + f7f7_38
    var h5 = f0f5_2 + f1f4_2 + f2f3_2 + f6f9_38 + f7f8_38
    var h6 = f0f6_2 + f1f5_4 + f2f4_2 + f3f3_2 + f7f9_76 + f8f8_19
    var h7 = f0f7_2 + f1f6_2 + f2f5_2 + f3f4_2 + f8f9_38
    var h8 = f0f8_2 + f1f7_4 + f2f6_2 + f3f5_4 + f4f4 + f9f9_38
    var h9 = f0f9_2 + f1f8_2 + f2f7_2 + f3f6_2 + f4f5_2
    var carry0: Long
    val carry1: Long
    val carry2: Long
    val carry3: Long
    var carry4: Long
    val carry5: Long
    val carry6: Long
    val carry7: Long
    val carry8: Long
    val carry9: Long

    h0 += h0
    h1 += h1
    h2 += h2
    h3 += h3
    h4 += h4
    h5 += h5
    h6 += h6
    h7 += h7
    h8 += h8
    h9 += h9

    carry0 = h0 + (1 shl 25).toLong() shr 26
    h1 += carry0
    h0 -= carry0 shl 26
    carry4 = h4 + (1 shl 25).toLong() shr 26
    h5 += carry4
    h4 -= carry4 shl 26

    carry1 = h1 + (1 shl 24).toLong() shr 25
    h2 += carry1
    h1 -= carry1 shl 25
    carry5 = h5 + (1 shl 24).toLong() shr 25
    h6 += carry5
    h5 -= carry5 shl 25

    carry2 = h2 + (1 shl 25).toLong() shr 26
    h3 += carry2
    h2 -= carry2 shl 26
    carry6 = h6 + (1 shl 25).toLong() shr 26
    h7 += carry6
    h6 -= carry6 shl 26

    carry3 = h3 + (1 shl 24).toLong() shr 25
    h4 += carry3
    h3 -= carry3 shl 25
    carry7 = h7 + (1 shl 24).toLong() shr 25
    h8 += carry7
    h7 -= carry7 shl 25

    carry4 = h4 + (1 shl 25).toLong() shr 26
    h5 += carry4
    h4 -= carry4 shl 26
    carry8 = h8 + (1 shl 25).toLong() shr 26
    h9 += carry8
    h8 -= carry8 shl 26

    carry9 = h9 + (1 shl 24).toLong() shr 25
    h0 += carry9 * 19
    h9 -= carry9 shl 25

    carry0 = h0 + (1 shl 25).toLong() shr 26
    h1 += carry0
    h0 -= carry0 shl 26

    h[0] = h0.toInt()
    h[1] = h1.toInt()
    h[2] = h2.toInt()
    h[3] = h3.toInt()
    h[4] = h4.toInt()
    h[5] = h5.toInt()
    h[6] = h6.toInt()
    h[7] = h7.toInt()
    h[8] = h8.toInt()
    h[9] = h9.toInt()
}

fun fe_sub(h: IntArray, f: IntArray, g: IntArray) {
    h[0] = f[0] - g[0]
    h[1] = f[1] - g[1]
    h[2] = f[2] - g[2]
    h[3] = f[3] - g[3]
    h[4] = f[4] - g[4]
    h[5] = f[5] - g[5]
    h[6] = f[6] - g[6]
    h[7] = f[7] - g[7]
    h[8] = f[8] - g[8]
    h[9] = f[9] - g[9]
}

fun fe_tobytes(s: ByteArray, h: IntArray) {
    var h0 = h[0]
    var h1 = h[1]
    var h2 = h[2]
    var h3 = h[3]
    var h4 = h[4]
    var h5 = h[5]
    var h6 = h[6]
    var h7 = h[7]
    var h8 = h[8]
    var h9 = h[9]
    var q: Int
    val carry0: Int
    val carry1: Int
    val carry2: Int
    val carry3: Int
    val carry4: Int
    val carry5: Int
    val carry6: Int
    val carry7: Int
    val carry8: Int
    val carry9: Int

    q = 19 * h9 + (1 shl 24) shr 25
    q = h0 + q shr 26
    q = h1 + q shr 25
    q = h2 + q shr 26
    q = h3 + q shr 25
    q = h4 + q shr 26
    q = h5 + q shr 25
    q = h6 + q shr 26
    q = h7 + q shr 25
    q = h8 + q shr 26
    q = h9 + q shr 25

    h0 += 19 * q

    carry0 = h0 shr 26
    h1 += carry0
    h0 -= carry0 shl 26
    carry1 = h1 shr 25
    h2 += carry1
    h1 -= carry1 shl 25
    carry2 = h2 shr 26
    h3 += carry2
    h2 -= carry2 shl 26
    carry3 = h3 shr 25
    h4 += carry3
    h3 -= carry3 shl 25
    carry4 = h4 shr 26
    h5 += carry4
    h4 -= carry4 shl 26
    carry5 = h5 shr 25
    h6 += carry5
    h5 -= carry5 shl 25
    carry6 = h6 shr 26
    h7 += carry6
    h6 -= carry6 shl 26
    carry7 = h7 shr 25
    h8 += carry7
    h7 -= carry7 shl 25
    carry8 = h8 shr 26
    h9 += carry8
    h8 -= carry8 shl 26
    carry9 = h9 shr 25
    h9 -= carry9 shl 25

    s[0] = (h0 shr 0).toByte()
    s[1] = (h0 shr 8).toByte()
    s[2] = (h0 shr 16).toByte()
    s[3] = (h0 shr 24 or (h1 shl 2)).toByte()
    s[4] = (h1 shr 6).toByte()
    s[5] = (h1 shr 14).toByte()
    s[6] = (h1 shr 22 or (h2 shl 3)).toByte()
    s[7] = (h2 shr 5).toByte()
    s[8] = (h2 shr 13).toByte()
    s[9] = (h2 shr 21 or (h3 shl 5)).toByte()
    s[10] = (h3 shr 3).toByte()
    s[11] = (h3 shr 11).toByte()
    s[12] = (h3 shr 19 or (h4 shl 6)).toByte()
    s[13] = (h4 shr 2).toByte()
    s[14] = (h4 shr 10).toByte()
    s[15] = (h4 shr 18).toByte()
    s[16] = (h5 shr 0).toByte()
    s[17] = (h5 shr 8).toByte()
    s[18] = (h5 shr 16).toByte()
    s[19] = (h5 shr 24 or (h6 shl 1)).toByte()
    s[20] = (h6 shr 7).toByte()
    s[21] = (h6 shr 15).toByte()
    s[22] = (h6 shr 23 or (h7 shl 3)).toByte()
    s[23] = (h7 shr 5).toByte()
    s[24] = (h7 shr 13).toByte()
    s[25] = (h7 shr 21 or (h8 shl 4)).toByte()
    s[26] = (h8 shr 4).toByte()
    s[27] = (h8 shr 12).toByte()
    s[28] = (h8 shr 20 or (h9 shl 6)).toByte()
    s[29] = (h9 shr 2).toByte()
    s[30] = (h9 shr 10).toByte()
    s[31] = (h9 shr 18).toByte()
}