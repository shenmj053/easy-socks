package org.easysocks.ssserver.obfs.entity;

public class TlsServerHello {
    short contentType = 0x16;
    int version = 0x0301;
    int len = 91;

    short handshakeType = 2;
    short handshakeLen1 = 0;
    int handshakeLen2 = 87;
    int handshakeVersion = 0x0303;

    long randomUnixTime;
    short[] randomBytes = new short[28];
    short  sessionIdLen = 32;
    short[] sessionId = new short[32];

    int cipherSuite = 0xcca8;
    short compMethod;
    int extLen;

    int extRenegoInfoType = 0xff01;
    int extRenegoInfoExtLen = 1;
    short extRenegoInfoLen;

    int extendedMasterSecretType = 0x0017;
    int extendedMasterSecretExtLen;

    int ecPointFormatsExtType = 0x000b;
    int ecPointFormatsExtLen = 2;
    short ecPointFormatsLen = 1;
    short[] ecPointFormats = new short[1];
}
