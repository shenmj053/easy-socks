package org.easysocks.ssserver.obfs.entity;

public class TlsEncryptedHandshake {
    short contentType = 0x16;
    int version = 0x0303;
    int len;
    /**
     * len
     */
     short[] msg;
}
