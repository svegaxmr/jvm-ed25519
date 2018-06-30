package com.svega.crypto.ed25519

import com.svega.crypto.common.CryptoOps.load_3
import com.svega.crypto.common.CryptoOps.load_4
import com.svega.crypto.ed25519.objects.ge_cached
import com.svega.crypto.ed25519.objects.ge_p1p1
import com.svega.crypto.ed25519.objects.ge_p3
import com.svega.crypto.ed25519.objects.ge_precomp
import com.svega.crypto.ed25519.objects.ge_p2

/**
 * Contains all functions starting with ge_
 */
fun ge_add(r: ge_p1p1, p: ge_p3, q: ge_cached) {
    val t0 = IntArray(10)
    fe_add(r.X, p.Y, p.X)
    fe_sub(r.Y, p.Y, p.X)
    fe_mul(r.Z, r.X, q.YplusX)
    fe_mul(r.Y, r.Y, q.YminusX)
    fe_mul(r.T, q.T2d, p.T)
    fe_mul(r.X, p.Z, q.Z)
    fe_add(t0, r.X, r.X)
    fe_sub(r.X, r.Z, r.Y)
    fe_add(r.Y, r.Z, r.Y)
    fe_add(r.Z, t0, r.T)
    fe_sub(r.T, t0, r.T)
}

fun slide(r: ByteArray, a: ByteArray) {
    var b: Int
    var k: Int

    for(i in 0 until 256) {
        //CONVERT r[i] = 1 & (a[i shr 3] shr (i & 7))
        r[i] = (1 and a[i shr 3].toInt().ushr(i and 7)).toByte()
    }

    for(i in 0 until 256) {
        if (r[i].toInt() != 0) {
            b = 1
            while (b <= 6 && i + b < 256) {
                if (r[i + b].toInt() != 0) {
                    if (r[i] + (r[i + b].toInt() shl b) <= 15) {
                        val temp = (r[i + b].toInt().shl(b)).toByte()
                        val temp2 = r[i]
                        r[i] = (temp + temp2).toByte()
                        r[i + b] = 0
                    } else if (r[i] - (r[i + b].toInt() shl b) >= -15) {
                        val temp = (r[i + b].toInt() shl b).toByte()
                        val temp2 = r[i]
                        r[i] = (temp2 - temp).toByte()
                        k = i + b
                        while (k < 256) {
                            if (r[k].toInt() == 0) {
                                r[k] = 1
                                break
                            }
                            r[k] = 0
                            ++k
                        }
                    } else
                        break
                }
                ++b
            }
        }
    }
}

val Bi = Array<ge_precomp>(8, { i ->
    when(i){
        0 -> ge_precomp(
                intArrayOf(25967493,-14356035,29566456,3660896,-12694345,4014787,27544626,-11754271,-6079156,2047605 ),
                intArrayOf(-12545711,934262,-2722910,3049990,-727428,9406986,12720692,5043384,19500929,-15469378 ),
                intArrayOf(-8738181,4489570,9688441,-14785194,10184609,-12363380,29287919,11864899,-24514362,-4438546 )
        )
        1 -> ge_precomp(
                intArrayOf(15636291,-9688557,24204773,-7912398,616977,-16685262,27787600,-14772189,28944400,-1550024 ),
                intArrayOf(16568933,4717097,-11556148,-1102322,15682896,-11807043,16354577,-11775962,7689662,11199574 ),
                intArrayOf(30464156,-5976125,-11779434,-15670865,23220365,15915852,7512774,10017326,-17749093,-9920357 )
        )
        2 -> ge_precomp(
                intArrayOf(10861363,11473154,27284546,1981175,-30064349,12577861,32867885,14515107,-15438304,10819380 ),
                intArrayOf(4708026,6336745,20377586,9066809,-11272109,6594696,-25653668,12483688,-12668491,5581306 ),
                intArrayOf(19563160,16186464,-29386857,4097519,10237984,-4348115,28542350,13850243,-23678021,-15815942 )
        )
        3 -> ge_precomp(
                intArrayOf(5153746,9909285,1723747,-2777874,30523605,5516873,19480852,5230134,-23952439,-15175766 ),
                intArrayOf(-30269007,-3463509,7665486,10083793,28475525,1649722,20654025,16520125,30598449,7715701 ),
                intArrayOf(28881845,14381568,9657904,3680757,-20181635,7843316,-31400660,1370708,29794553,-1409300 )
        )
        4 -> ge_precomp(
                intArrayOf(-22518993,-6692182,14201702,-8745502,-23510406,8844726,18474211,-1361450,-13062696,13821877 ),
                intArrayOf(-6455177,-7839871,3374702,-4740862,-27098617,-10571707,31655028,-7212327,18853322,-14220951 ),
                intArrayOf(4566830,-12963868,-28974889,-12240689,-7602672,-2830569,-8514358,-10431137,2207753,-3209784 )
        )
        5 -> ge_precomp(
                intArrayOf(-25154831,-4185821,29681144,7868801,-6854661,-9423865,-12437364,-663000,-31111463,-16132436 ),
                intArrayOf(25576264,-2703214,7349804,-11814844,16472782,9300885,3844789,15725684,171356,6466918 ),
                intArrayOf(23103977,13316479,9739013,-16149481,817875,-15038942,8965339,-14088058,-30714912,16193877 )
        )
        6 -> ge_precomp(
                intArrayOf(-33521811,3180713,-2394130,14003687,-16903474,-16270840,17238398,4729455,-18074513,9256800 ),
                intArrayOf(-25182317,-4174131,32336398,5036987,-21236817,11360617,22616405,9761698,-19827198,630305 ),
                intArrayOf(-13720693,2639453,-24237460,-7406481,9494427,-5774029,-6554551,-15960994,-2449256,-14291300 )
        )
        7 -> ge_precomp(
                intArrayOf(-3151181,-5046075,9282714,6866145,-31907062,-863023,-18940575,15033784,25105118,-7894876 ),
                intArrayOf(-24326370,15950226,-31801215,-14592823,-11662737,-5090925,1573892,-2625887,2198790,-15804619 ),
                intArrayOf(-3099351,10324967,-2241613,7453183,-5446979,-2735503,-13812022,-16236442,-32461234,-12290683 )
        )
        else -> ge_precomp(intArrayOf(), intArrayOf(), intArrayOf())
    }
})

fun ge_double_scalarmult_vartime(r: ge_p2, a: ByteArray, A: ge_p3, b: ByteArray) {
    val aslide = ByteArray(256)
    val bslide = ByteArray(256)
    val Ai = Array(8, {ge_cached()}) /* A,3A,5A,7A,9A,11A,13A,15A */
    val t = ge_p1p1()
    val u = ge_p3()
    val A2 = ge_p3()
    var i: Int

    slide(aslide, a)
    slide(bslide, b)

    ge_p3_to_cached(Ai[0], A)
    ge_p3_dbl(t, A)
    ge_p1p1_to_p3(A2, t)
    ge_add(t, A2, Ai[0])
    ge_p1p1_to_p3(u, t)
    ge_p3_to_cached(Ai[1], u)
    ge_add(t, A2, Ai[1])
    ge_p1p1_to_p3(u, t)
    ge_p3_to_cached(Ai[2], u)
    ge_add(t, A2, Ai[2])
    ge_p1p1_to_p3(u, t)
    ge_p3_to_cached(Ai[3], u)
    ge_add(t, A2, Ai[3])
    ge_p1p1_to_p3(u, t)
    ge_p3_to_cached(Ai[4], u)
    ge_add(t, A2, Ai[4])
    ge_p1p1_to_p3(u, t)
    ge_p3_to_cached(Ai[5], u)
    ge_add(t, A2, Ai[5])
    ge_p1p1_to_p3(u, t)
    ge_p3_to_cached(Ai[6], u)
    ge_add(t, A2, Ai[6])
    ge_p1p1_to_p3(u, t)
    ge_p3_to_cached(Ai[7], u)

    ge_p2_0(r)

    i = 255
    while (i >= 0) {
        if (aslide[i].toInt() != 0 || bslide[i].toInt() != 0) break
        --i
    }

    while (i >= 0) {
        ge_p2_dbl(t, r)

        if (aslide[i] > 0) {
            ge_p1p1_to_p3(u, t)
            ge_add(t, u, Ai[aslide[i] / 2])
        } else if (aslide[i] < 0) {
            ge_p1p1_to_p3(u, t)
            ge_sub(t, u, Ai[-aslide[i] / 2])
        }

        if (bslide[i] > 0) {
            ge_p1p1_to_p3(u, t)
            ge_madd(t, u, Bi[bslide[i] / 2])
        } else if (bslide[i] < 0) {
            ge_p1p1_to_p3(u, t)
            ge_msub(t, u, Bi[-bslide[i] / 2])
        }

        ge_p1p1_to_p2(r, t)
        --i
    }
}

var ge_frombytes_negate_vartime_d = intArrayOf(
        //CONVERT #include "ge_frombytes_negate_vartime_d.h"
        -10913610, 13857413, -15372611, 6949391, 114729, -8787816, -6275908, -3247719, -18696448, -12055116)

var ge_frombytes_negate_vartime_sqrtm1 = intArrayOf(
        //CONVERT #include "ge_frombytes_negate_vartime_sqrtm1.h"
        -32595792, -7943725, 9377950, 3500415, 12389472, -272473, -25146209, -2005654, 326686, 11406482)

fun ge_frombytes_negate_vartime(h: ge_p3, s: ByteArray): Boolean {
    val u = IntArray(10)
    val v = IntArray(10)
    val v3 = IntArray(10)
    val vxx = IntArray(10)
    val check = IntArray(10)

    fe_frombytes(h.Y, s)
    fe_1(h.Z)
    fe_sq(u, h.Y)
    fe_mul(v, u, ge_frombytes_negate_vartime_d)
    fe_sub(u, u, h.Z)       /* u = y^2-1 */
    fe_add(v, v, h.Z)       /* v = dy^2+1 */

    fe_sq(v3, v)
    fe_mul(v3, v3, v)        /* v3 = v^3 */
    fe_sq(h.X, v3)
    fe_mul(h.X, h.X, v)
    fe_mul(h.X, h.X, u)    /* x = uv^7 */

    fe_pow22523(h.X, h.X) /* x = (uv^7)^((q-5)/8) */
    fe_mul(h.X, h.X, v3)
    fe_mul(h.X, h.X, u)    /* x = uv^3(uv^7)^((q-5)/8) */

    fe_sq(vxx, h.X)
    fe_mul(vxx, vxx, v)
    fe_sub(check, vxx, u)    /* vx^2-u */
    if (fe_isnonzero(check) != 0) {
        fe_add(check, vxx, u)  /* vx^2+u */
        if (fe_isnonzero(check) != 0)
            return false
        fe_mul(h.X, h.X, ge_frombytes_negate_vartime_sqrtm1)
    }

    if (fe_isnegative(h.X) == s[31].toInt().ushr(7) and 0x01) {
        fe_neg(h.X, h.X)
    }

    fe_mul(h.T, h.X, h.Y)
    return true
}

fun ge_madd(r: ge_p1p1, p: ge_p3, q: ge_precomp) {
    val t0 = IntArray(10)
    fe_add(r.X, p.Y, p.X)
    fe_sub(r.Y, p.Y, p.X)
    fe_mul(r.Z, r.X, q.yplusx)
    fe_mul(r.Y, r.Y, q.yminusx)
    fe_mul(r.T, q.xy2d, p.T)
    fe_add(t0, p.Z, p.Z)
    fe_sub(r.X, r.Z, r.Y)
    fe_add(r.Y, r.Z, r.Y)
    fe_add(r.Z, t0, r.T)
    fe_sub(r.T, t0, r.T)
}

fun ge_msub(r: ge_p1p1, p: ge_p3, q: ge_precomp) {
    val t0 = IntArray(10)
    fe_add(r.X, p.Y, p.X)
    fe_sub(r.Y, p.Y, p.X)
    fe_mul(r.Z, r.X, q.yminusx)
    fe_mul(r.Y, r.Y, q.yplusx)
    fe_mul(r.T, q.xy2d, p.T)
    fe_add(t0, p.Z, p.Z)
    fe_sub(r.X, r.Z, r.Y)
    fe_add(r.Y, r.Z, r.Y)
    fe_sub(r.Z, t0, r.T)
    fe_add(r.T, t0, r.T)
}

fun ge_p1p1_to_p2(r: ge_p2, p: ge_p1p1) {
    fe_mul(r.X, p.X, p.T)
    fe_mul(r.Y, p.Y, p.Z)
    fe_mul(r.Z, p.Z, p.T)
}

fun ge_p1p1_to_p3(r: ge_p3, p: ge_p1p1) {
    fe_mul(r.X, p.X, p.T)
    fe_mul(r.Y, p.Y, p.Z)
    fe_mul(r.Z, p.Z, p.T)
    fe_mul(r.T, p.X, p.Y)
}

fun ge_p2_0(h: ge_p2) {
    fe_0(h.X)
    fe_1(h.Y)
    fe_1(h.Z)
}

fun ge_p2_dbl(r: ge_p1p1, p: ge_p2) {
    val t0 = IntArray(10)
    fe_sq(r.X, p.X)
    fe_sq(r.Z, p.Y)
    fe_sq2(r.T, p.Z)
    fe_add(r.Y, p.X, p.Y)
    fe_sq(t0, r.Y)
    fe_add(r.Y, r.Z, r.X)
    fe_sub(r.Z, r.Z, r.X)
    fe_sub(r.X, t0, r.Y)
    fe_sub(r.T, r.T, r.Z)
}

fun ge_p3_0(h: ge_p3) {
    fe_0(h.X)
    fe_1(h.Y)
    fe_1(h.Z)
    fe_0(h.T)
}

fun ge_p3_dbl(r: ge_p1p1, p: ge_p3) {
    val q = ge_p2()
    ge_p3_to_p2(q, p)
    ge_p2_dbl(r, q)
}

var ge_p3_to_cached_d2 = intArrayOf(-21827239, -5839606, -30745221, 13898782, 229458, 15978800, -12551817, -6495438, 29715968, 9444199)

fun ge_p3_to_cached(r: ge_cached, p: ge_p3) {
    fe_add(r.YplusX, p.Y, p.X)
    fe_sub(r.YminusX, p.Y, p.X)
    fe_copy(r.Z, p.Z)
    fe_mul(r.T2d, p.T, ge_p3_to_cached_d2)
}

fun ge_p3_to_p2(r: ge_p2, p: ge_p3) {
    fe_copy(r.X, p.X)
    fe_copy(r.Y, p.Y)
    fe_copy(r.Z, p.Z)
}

fun ge_p3_tobytes(s: ByteArray, h: ge_p3) {
    val recip = IntArray(10)
    val x = IntArray(10)
    val y = IntArray(10)

    fe_invert(recip, h.Z)
    fe_mul(x, h.X, recip)
    fe_mul(y, h.Y, recip)
    fe_tobytes(s, y)
    s[31] = ((s[31].toInt() and 0xFF xor (fe_isnegative(x) shl 7))).toByte()
}

fun ge_precomp_0(h: ge_precomp) {
    fe_1(h.yplusx)
    fe_1(h.yminusx)
    fe_0(h.xy2d)
}

fun equal(b: Byte, c: Byte): Int {
    val ub = b.toInt()
    val uc = c.toInt()
    val x = ub xor uc
    var y = x
    y -= 1
    y = y ushr 31
    return y
}

fun negative(b: Byte): Int {
    var x = b.toLong()
    x = x ushr 63
    return x.toInt()
}

fun cmov(t: ge_precomp, u: ge_precomp, b: Int) {
    fe_cmov(t.yplusx, u.yplusx, b)
    fe_cmov(t.yminusx, u.yminusx, b)
    fe_cmov(t.xy2d, u.xy2d, b)
}

fun select(t: ge_precomp, pos: Int, b: Byte) {
    val base = ge_precomp_base.base

    val minust = ge_precomp()
    val bnegative = negative(b)
    val babs = b - (-bnegative and b.toInt() shl 1)

    ge_precomp_0(t)
    cmov(t, base[pos][0], equal(babs.toByte(), 1.toByte()))
    cmov(t, base[pos][1], equal(babs.toByte(), 2.toByte()))
    cmov(t, base[pos][2], equal(babs.toByte(), 3.toByte()))
    cmov(t, base[pos][3], equal(babs.toByte(), 4.toByte()))
    cmov(t, base[pos][4], equal(babs.toByte(), 5.toByte()))
    cmov(t, base[pos][5], equal(babs.toByte(), 6.toByte()))
    cmov(t, base[pos][6], equal(babs.toByte(), 7.toByte()))
    cmov(t, base[pos][7], equal(babs.toByte(), 8.toByte()))
    fe_copy(minust.yplusx, t.yminusx)
    fe_copy(minust.yminusx, t.yplusx)
    fe_neg(minust.xy2d, t.xy2d)
    cmov(t, minust, bnegative)
}

fun ge_scalarmult_base(h: ge_p3, a: ByteArray) {
    val e = ByteArray(64)
    var carry: Byte
    val r = ge_p1p1()
    val s = ge_p2()
    val t = ge_precomp()

    for(i in 0 until 32) {
        e[2 * i + 0] = (a[i].toInt() and 15).toByte()
        e[2 * i + 1] = (a[i].toInt() ushr 4 and 15).toByte()
    }

    carry = 0
    for(i in 0 until 63) {
        e[i] = (e[i] + carry).toByte()
        carry = (e[i] + 8).toByte()
        carry = (carry.toInt() shr 4 and 0xFF).toByte()
        e[i] = (e[i] - (carry.toInt() shl 4 and 0xFF).toByte()).toByte()
    }
    e[63] = (e[63] + carry).toByte()

    ge_p3_0(h)
    for(i in 1 until 64 step 2) {
        select(t, i / 2, e[i])
        ge_madd(r, h, t)
        ge_p1p1_to_p3(h, r)
    }

    ge_p3_dbl(r, h)
    ge_p1p1_to_p2(s, r)
    ge_p2_dbl(r, s)
    ge_p1p1_to_p2(s, r)
    ge_p2_dbl(r, s)
    ge_p1p1_to_p2(s, r)
    ge_p2_dbl(r, s)
    ge_p1p1_to_p3(h, r)

    for(i in 0 until 64 step 2) {
        select(t, i / 2, e[i])
        ge_madd(r, h, t)
        ge_p1p1_to_p3(h, r)
    }
}

fun ge_sub(r: ge_p1p1, p: ge_p3, q: ge_cached) {
    val t0 = IntArray(10)
    fe_add(r.X, p.Y, p.X)
    fe_sub(r.Y, p.Y, p.X)
    fe_mul(r.Z, r.X, q.YminusX)
    fe_mul(r.Y, r.Y, q.YplusX)
    fe_mul(r.T, q.T2d, p.T)
    fe_mul(r.X, p.Z, q.Z)
    fe_add(t0, r.X, r.X)
    fe_sub(r.X, r.Z, r.Y)
    fe_add(r.Y, r.Z, r.Y)
    fe_sub(r.Z, t0, r.T)
    fe_add(r.T, t0, r.T)
}

fun ge_tobytes(s: ByteArray, h: ge_p2) {
    val recip = IntArray(10)
    val x = IntArray(10)
    val y = IntArray(10)

    fe_invert(recip, h.Z)
    fe_mul(x, h.X, recip)
    fe_mul(y, h.Y, recip)
    fe_tobytes(s, y)
    s[31] = (s[31].toInt() and 0xFF xor (fe_isnegative(x) shl 7)).toByte()
}

val fe_d = intArrayOf(-10913610, 13857413, -15372611, 6949391, 114729, -8787816, -6275908, -3247719, -18696448,-12055116)
val fe_sqrtm1 = intArrayOf(-32595792, -7943725, 9377950, 3500415, 12389472, -272473, -25146209, -2005654, 326686, 11406482)

fun ge_frombytes_vartime(h: ge_p3, s: ByteArray): Int {
    val u = IntArray(10)
    val v = IntArray(10)
    val vxx = IntArray(10)
    val check = IntArray(10)

    /* From fe_frombytes.c */

    var h0 = load_4(s, 0)
    var h1 = load_3(s, 4) shl 6
    var h2 = load_3(s, 7) shl 5
    var h3 = load_3(s, 10) shl 3
    var h4 = load_3(s, 13) shl 2
    var h5 = load_4(s, 16)
    var h6 = load_3(s, 20) shl 7
    var h7 = load_3(s, 23) shl 5
    var h8 = load_3(s, 26) shl 4
    var h9 = (load_3(s, 29) and 8388607) shl 2
    var carry0: Long
    var carry1: Long
    var carry2: Long
    var carry3: Long
    var carry4: Long
    var carry5: Long
    var carry6: Long
    var carry7: Long
    var carry8: Long
    var carry9: Long

    /* Validate the number to be canonical */
    if (h9 == 33554428L && h8 == 268435440L && h7 == 536870880L && h6 == 2147483520L &&
            h5 == 4294967295L && h4 == 67108860L && h3 == 134217720L && h2 == 536870880L &&
            h1 == 1073741760L && h0 >= 4294967277L) {
        return -1
    }

    carry9 = h9 + (1 shl 24) shr 25
    h0 += carry9 * 19
    h9 -= (carry9 shl 25)
    carry1 = h1 + (1 shl 24) shr 25
    h2 += carry1
    h1 -= (carry1 shl 25)
    carry3 = h3 + (1 shl 24) shr 25
    h4 += carry3
    h3 -= (carry3 shl 25)
    carry5 = h5 + (1 shl 24) shr 25
    h6 += carry5
    h5 -= (carry5 shl 25)
    carry7 = h7 + (1 shl 24) shr 25
    h8 += carry7
    h7 -= (carry7 shl 25)
    carry0 = h0 + (1 shl 25) shr 26
    h1 += carry0
    h0 -= (carry0 shl 26)
    carry2 = h2 + (1 shl 25) shr 26
    h3 += carry2
    h2 -= (carry2 shl 26)
    carry4 = h4 + (1 shl 25) shr 26
    h5 += carry4
    h4 -= (carry4 shl 26)
    carry6 = h6 + (1 shl 25) shr 26
    h7 += carry6
    h6 -= (carry6 shl 26)
    carry8 = h8 + (1 shl 25) shr 26
    h9 += carry8
    h8 -= (carry8 shl 26)

    h.Y[0] = h0.toInt()
    h.Y[1] = h1.toInt()
    h.Y[2] = h2.toInt()
    h.Y[3] = h3.toInt()
    h.Y[4] = h4.toInt()
    h.Y[5] = h5.toInt()
    h.Y[6] = h6.toInt()
    h.Y[7] = h7.toInt()
    h.Y[8] = h8.toInt()
    h.Y[9] = h9.toInt()

    /* End fe_frombytes.c */

    fe_1(h.Z)
    fe_sq(u, h.Y)
    fe_mul(v, u, fe_d)
    fe_sub(u, u, h.Z)       /* u = y^2-1 */
    fe_add(v, v, h.Z)       /* v = dy^2+1 */

    fe_divpowm1(h.X, u, v) /* x = uv^3(uv^7)^((q-5)/8) */

    fe_sq(vxx, h.X)
    fe_mul(vxx, vxx, v)
    fe_sub(check, vxx, u)    /* vx^2-u */
    if (fe_isnonzero(check) != 0) {
        fe_add(check, vxx, u)  /* vx^2+u */
        if (fe_isnonzero(check) != 0) {
            return -1
        }
        fe_mul(h.X, h.X, fe_sqrtm1)
    }

    if (fe_isnegative(h.X) != ((s[31].toInt() shr 7)) and 0xFF) {
        /* If x = 0, the sign must be positive */
        if (fe_isnonzero(h.X) == 0) {
        return -1
    }
        fe_neg(h.X, h.X)
    }

    fe_mul(h.T, h.X, h.Y)
    return 0
}


fun ge_mul8(r: ge_p1p1, t: ge_p2) {
    val u = ge_p2()
    ge_p2_dbl(r, t)
    ge_p1p1_to_p2(u, r)
    ge_p2_dbl(r, u)
    ge_p1p1_to_p2(u, r)
    ge_p2_dbl(r, u)
}

fun ge_scalarmult(r: ge_p2, a: ByteArray, A: ge_p3) {
    val e = ByteArray(64)
    var carry2: Int
    val Ai = Array(8, {ge_cached()})
    val t = ge_p1p1()
    val u = ge_p3()

    var carry = 0 /* 0..1 */
    for (i in 0 until 31) {
        carry += a[i] /* 0..256 */
        carry2 = (carry + 8) shr 4 /* 0..16 */
        e[2 * i] = (carry - (carry2 shl 4)).toByte() /* -8..7 */
        carry = (carry2 + 8) shr 4 /* 0..1 */
        e[2 * i + 1] = (carry2 - (carry shl 4)).toByte() /* -8..7 */
    }
    carry += a[31] /* 0..128 */
    carry2 = (carry + 8) shr 4 /* 0..8 */
    e[62] = (carry - (carry2 shl 4)).toByte() /* -8..7 */
    e[63] = carry2.toByte() /* 0..8 */

    ge_p3_to_cached(Ai[0], A)
    for (i in 0 until 7) {
        ge_add(t, A, Ai[i])
        ge_p1p1_to_p3(u, t)
        ge_p3_to_cached(Ai[i + 1], u)
    }

    ge_p2_0(r)
    for (i in 63 downTo 0) {
        val b = e[i]
        val bnegative = negative(b)
        val babs = Math.abs(bnegative).toByte()
        val cur = ge_cached()
        val minuscur = ge_cached()
        ge_p2_dbl(t, r)
        ge_p1p1_to_p2(r, t)
        ge_p2_dbl(t, r)
        ge_p1p1_to_p2(r, t)
        ge_p2_dbl(t, r)
        ge_p1p1_to_p2(r, t)
        ge_p2_dbl(t, r)
        ge_p1p1_to_p3(u, t)
        ge_cached_0(cur)
        ge_cached_cmov(cur, Ai[0], equal(babs, 1))
        ge_cached_cmov(cur, Ai[1], equal(babs, 2))
        ge_cached_cmov(cur, Ai[2], equal(babs, 3))
        ge_cached_cmov(cur, Ai[3], equal(babs, 4))
        ge_cached_cmov(cur, Ai[4], equal(babs, 5))
        ge_cached_cmov(cur, Ai[5], equal(babs, 6))
        ge_cached_cmov(cur, Ai[6], equal(babs, 7))
        ge_cached_cmov(cur, Ai[7], equal(babs, 8))
        fe_copy(minuscur.YplusX, cur.YminusX)
        fe_copy(minuscur.YminusX, cur.YplusX)
        fe_copy(minuscur.Z, cur.Z)
        fe_neg(minuscur.T2d, cur.T2d)
        ge_cached_cmov(cur, minuscur, bnegative)
        ge_add(t, u, cur)
        ge_p1p1_to_p2(r, t)
    }
}

fun ge_cached_0(r: ge_cached) {
    fe_1(r.YplusX)
    fe_1(r.YminusX)
    fe_1(r.Z)
    fe_0(r.T2d)
}

fun ge_cached_cmov(t: ge_cached, u: ge_cached, b: Int) {
    fe_cmov(t.YplusX, u.YplusX, b)
    fe_cmov(t.YminusX, u.YminusX, b)
    fe_cmov(t.Z, u.Z, b)
    fe_cmov(t.T2d, u.T2d, b)
}