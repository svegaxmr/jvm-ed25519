module jvm.ed25519 {
    requires kotlin.stdlib;
    requires jvm.crypto;

    exports com.svega.crypto.ed25519;
    exports com.svega.crypto.ed25519.objects;
}