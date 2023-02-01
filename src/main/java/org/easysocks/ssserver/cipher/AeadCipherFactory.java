package org.easysocks.ssserver.cipher;

import java.util.Optional;
import lombok.extern.slf4j.Slf4j;
import org.easysocks.ssserver.config.SsConfig;

@Slf4j
public class AeadCipherFactory {
    public static AeadCipher create(SsConfig ssConfig) throws IllegalArgumentException {
        Optional<AeadCipherEnum> aeadCipherEnumOptional = AeadCipherEnum.parse(ssConfig.getMethod());
        if (!aeadCipherEnumOptional.isPresent()) {
            log.error("Invalid AEAD cipher method {}", ssConfig.getMethod());
            throw new IllegalArgumentException("Invalid AEAD cipher method");
        }
        AeadCipherEnum aeadCipherEnum = aeadCipherEnumOptional.get();
        switch (aeadCipherEnum){
            case AEAD_CHACHA20_POLY1305:
                log.info("{} is used", aeadCipherEnum.getAlias());
                return new Chacha20AeadCipher(aeadCipherEnum, ssConfig.getPassword());
            case AEAD_AES_128_GCM:
            case AEAD_AES_256_GCM:
            default:
                log.info("{} is used", aeadCipherEnum.getAlias());
                return new Aes256GcmCipher(aeadCipherEnum, ssConfig.getPassword());
        }
    }

}
