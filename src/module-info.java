module jvm.ed25519 {
    requires kotlin.stdlib;
    requires jvm.crypto;
    requires svega.common.utils;

    exports com.svega.crypto.ed25519;
    exports com.svega.crypto.ed25519.objects;
}