package org.easysocks.ssserver.obfs.entity;

import io.netty.buffer.ByteBuf;
import io.netty.buffer.Unpooled;
import lombok.Data;

@Data
public class TlsServerHello {
    public static int byteLength = 95;
    short contentType = 0x16;
    int version = 0x0303;
    int len = 92;

    short handshakeType = 2;
    short handshakeLen1 = 0;
    int handshakeLen2 = 88;
    int handshakeVersion = 0x0303;

    long randomUnixTime;
    byte[] randomBytes = new byte[28];
    short  sessionIdLen = 32;
    byte[] sessionId = new byte[32];

    int cipherSuite = 0xcca8;
    short compMethod = 0x00;
    int extLen;

    int extRenegoInfoType = 0xff01;
    int extRenegoInfoExtLen = 0x0001;
    short extRenegoInfoLen = 0x00;

    int extendedMasterSecretType = 0x0017;
    int extendedMasterSecretExtLen;

    int ecPointFormatsExtType = 0x000b;
    int ecPointFormatsExtLen = 2;
    short ecPointFormatsLen = 1;
    short[] ecPointFormats = new short[1];

    public static ByteBuf encode(TlsServerHello content) {
        ByteBuf bf = Unpooled.buffer();
        bf.writeByte(content.getContentType());
        bf.writeShort(content.getVersion());
        bf.writeShort(content.getLen());

        bf.writeByte(content.getHandshakeType());
        bf.writeByte(content.getHandshakeLen1());
        bf.writeShort(content.getHandshakeLen2());
        bf.writeShort(content.getHandshakeVersion());

        bf.writeInt((int)content.getRandomUnixTime());
        for (short b: content.getRandomBytes()) {
            bf.writeByte(b);
        }
        bf.writeByte(content.getSessionIdLen());
        for (short b: content.getSessionId()) {
            bf.writeByte(b);
        }
        bf.writeShort(content.getCipherSuite());
        bf.writeByte(content.getCompMethod());
        bf.writeShort(content.getExtLen());

        bf.writeShort(content.getExtRenegoInfoType());
        bf.writeShort(content.getExtRenegoInfoExtLen());
        bf.writeByte(content.getExtRenegoInfoLen());

        bf.writeShort(content.getExtendedMasterSecretType());
        bf.writeShort(content.getExtendedMasterSecretExtLen());

        bf.writeShort(content.getEcPointFormatsExtType());
        bf.writeShort(content.getEcPointFormatsExtLen());
        bf.writeByte(content.getEcPointFormatsLen());
        bf.writeByte(content.getEcPointFormats()[0]);
        return bf;
    }
}
