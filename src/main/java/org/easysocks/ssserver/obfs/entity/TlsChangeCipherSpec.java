package org.easysocks.ssserver.obfs.entity;

public class TlsChangeCipherSpec {
    short contentType = 0x14;
    int version = 0x0303;
    int len = 0x0001;
    short msg = 0x01;
}
