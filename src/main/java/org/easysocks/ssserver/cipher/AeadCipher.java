package org.easysocks.ssserver.cipher;

public interface AeadCipher {
    byte[] encrypt(byte[] src) throws Exception;
    byte[] decrypt(byte[] src) throws Exception;
}
