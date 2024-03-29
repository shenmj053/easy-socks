package org.easysocks.ssserver.obfs.entity;

import io.netty.buffer.ByteBuf;
import io.netty.buffer.Unpooled;
import lombok.Data;

@Data
public class TlsExtOthers {
    public static int byteLength = 66;

    int ecPointFormatsExtType = 0x000b;
    int ecPointFormatsExtLen = 4;
    short ecPointFormatsLen = 3;
    byte[] ecPointFormats = { 0x01, 0x00, 0x02 };

    int ellipticCurvesType = 0x000a;
    int ellipticCurvesExtLen = 10;
    int ellipticCurvesLen = 8;
    byte[] ellipticCurves = { 0x00, 0x1d, 0x00, 0x17, 0x00, 0x19, 0x00, 0x18 };

    int sigAlgosType = 0x000d;
    int sigAlgosExtLen = 32;
    int sigAlgosLen = 30;
    byte[] sigAlgos = {
        0x06, 0x01, 0x06, 0x02, 0x06, 0x03, 0x05, 0x01, 0x05, 0x02, 0x05, 0x03, 0x04, 0x01, 0x04, 0x02,
        0x04, 0x03, 0x03, 0x01, 0x03, 0x02, 0x03, 0x03, 0x02, 0x01, 0x02, 0x02, 0x02, 0x03
    };

    int encryptThenMacType = 0x0016;
    int encryptThenMacExtLen = 0x0000;

    int extendedMasterSecretType = 0x0017;
    int extendedMasterSecretExtLen = 0x0000;

    public static ByteBuf encode(TlsExtOthers content) {
        ByteBuf bf = Unpooled.buffer();
        bf.writeShort(content.getEcPointFormatsExtType());
        bf.writeShort(content.getEcPointFormatsExtLen());
        bf.writeByte(content.getEcPointFormatsLen());
        bf.writeBytes(content.getEcPointFormats());

        bf.writeShort(content.getEllipticCurvesType());
        bf.writeShort(content.getEllipticCurvesExtLen());
        bf.writeShort(content.getEllipticCurvesLen());
        bf.writeBytes(content.getEllipticCurves());

        bf.writeShort(content.getSigAlgosType());
        bf.writeShort(content.getSigAlgosExtLen());
        bf.writeShort(content.getSigAlgosLen());
        bf.writeBytes(content.getSigAlgos());

        bf.writeShort(content.getEncryptThenMacType());
        bf.writeShort(content.getEncryptThenMacExtLen());
        bf.writeShort(content.getExtendedMasterSecretType());
        bf.writeShort(content.getExtendedMasterSecretExtLen());

        return bf;
    }
}
