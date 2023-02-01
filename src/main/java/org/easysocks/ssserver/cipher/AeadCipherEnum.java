package org.easysocks.ssserver.cipher;

import java.util.Arrays;
import java.util.Optional;
import lombok.Getter;

/**
 * <a href="http://shadowsocks.org/guide/aead.html">AEAD</a>
 * AEAD stands for Authenticated Encryption with Associated Data.
 * AEAD ciphers simultaneously provide confidentiality, integrity, and authenticity.
 * They have excellent performance and power efficiency on modern hardware.
 * Users should use AEAD ciphers whenever possible.
 * The following AEAD ciphers are recommended.
 * Compliant Shadowsocks implementations must support AEAD_CHACHA20_POLY1305.
 * Implementations for devices with hardware AES acceleration
 * should also implement AEAD_AES_128_GCM and AEAD_AES_256_GCM.
 */
@Getter
public enum AeadCipherEnum {
    AEAD_CHACHA20_POLY1305("chacha20-ietf-poly1305",
        32,32,12,16),
    AEAD_AES_256_GCM("aes-256-gcm",
        32,32,12,16),
    AEAD_AES_128_GCM("aes-128-gcm",
        16,16,12,16);
    AeadCipherEnum(String alias, int keySize, int saltSize, int nonceSize, int tagSize) {
        this.alias = alias;
        this.keySize = keySize;
        this.saltSize = saltSize;
        this.nonceSize = nonceSize;
        this.tagSize = tagSize;
    }
    private final String alias;
    private final int keySize;
    private final int saltSize;
    private final int nonceSize;
    private final int tagSize;

    public static Optional<AeadCipherEnum> parse(String name) {
        return Arrays
            .stream(AeadCipherEnum.values())
            .filter(a -> a.getAlias().equals(name))
            .findFirst()
            .map(Optional::of)
            .orElse(Optional.empty());
    }
}
