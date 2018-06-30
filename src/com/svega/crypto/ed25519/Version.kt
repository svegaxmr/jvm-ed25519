package com.svega.crypto.ed25519

import com.svega.common.version.Extra
import com.svega.common.version.Version

class Version: Version(1, 1, 3,
        makeExtra(Extra.BETA, 1)){
    init {
        com.svega.common.version.Version.requires("com.svega.common", 0, 2)
        com.svega.common.version.Version.requires("com.svega.crypto.common", 0, 1)
    }
}