package com.svega.crypto.ed25519.objects

class ge_precomp {

    var yplusx: IntArray
    var yminusx: IntArray
    var xy2d: IntArray

    constructor() {
        yplusx = IntArray(10)
        yminusx = IntArray(10)
        xy2d = IntArray(10)
    }

    constructor(new_yplusx: IntArray, new_yminusx: IntArray,
                new_xy2d: IntArray) {
        yplusx = new_yplusx
        yminusx = new_yminusx
        xy2d = new_xy2d
    }
}
