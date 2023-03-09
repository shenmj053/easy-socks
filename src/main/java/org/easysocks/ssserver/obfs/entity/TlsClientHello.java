package org.easysocks.ssserver.obfs.entity;

import com.google.common.io.BaseEncoding;
import io.netty.buffer.ByteBuf;
import io.netty.buffer.Unpooled;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;


@Data
@Builder
@AllArgsConstructor
@NoArgsConstructor
public class TlsClientHello {
    public static int byteLength = 138;
    /**
     * java type is signed, so one big-ending byte need to stored as short,
     * other fields follow the same rule.
     */
    short contentType = 0x16;
    int version = 0x0303;
    int len;

    short handshakeType = 0x01;
    short handshakeLen1;
    int handshakeLen2;
    int handshakeVersion = 0x0303;

    long randomUnixTime;
    byte[] randomBytes = new byte[28];
    short sessionIdLen = 32;
    byte[] sessionId = new byte[32];
    int cipherSuitesLen = 56;
    short[] cipherSuites = {
        0xc0, 0x2c, 0xc0, 0x30, 0x00, 0x9f, 0xcc, 0xa9, 0xcc, 0xa8, 0xcc, 0xaa, 0xc0, 0x2b, 0xc0, 0x2f,
        0x00, 0x9e, 0xc0, 0x24, 0xc0, 0x28, 0x00, 0x6b, 0xc0, 0x23, 0xc0, 0x27, 0x00, 0x67, 0xc0, 0x0a,
        0xc0, 0x14, 0x00, 0x39, 0xc0, 0x09, 0xc0, 0x13, 0x00, 0x33, 0x00, 0x9d, 0x00, 0x9c, 0x00, 0x3d,
        0x00, 0x3c, 0x00, 0x35, 0x00, 0x2f, 0x00, 0xff
    };
    short compMethodsLen = 1;
    byte[] compMethods = { 0 };
    int extLen;

    public static ByteBuf encode(TlsClientHello content) {
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
        bf.writeShort(content.getCipherSuitesLen());
        for (short b: content.getCipherSuites()) {
            bf.writeByte(b);
        }
        bf.writeByte(content.getCompMethodsLen());
        bf.writeByte(content.getCompMethods()[0]);
        bf.writeShort(content.getExtLen());
        return bf;
    }

    public static TlsClientHello decode(ByteBuf buf) {
        return TlsClientHello
            .builder()
            .contentType(buf.readUnsignedByte())
            .version(buf.readUnsignedShort())
            .len(buf.readUnsignedShort())
            .handshakeType(buf.readUnsignedByte())
            .handshakeLen1(buf.readUnsignedByte())
            .handshakeLen2(buf.readUnsignedShort())
            .handshakeVersion(buf.readUnsignedShort())
            .randomUnixTime(buf.readUnsignedInt())
            .randomBytes(readBytes(buf, 28))
            .sessionIdLen(buf.readUnsignedByte())
            .sessionId(readBytes(buf, 32))
            .cipherSuitesLen(buf.readUnsignedShort())
            .cipherSuites(readUnsignedBytes(buf, 56))
            .compMethodsLen(buf.readUnsignedByte())
            .compMethods(readBytes(buf, 1))
            .extLen(buf.readUnsignedShort())
            .build();
    }

    public static short[] readUnsignedBytes(ByteBuf buf, int len) {
        short[] result = new short[len];
        for(int i = 0; i < len; i++) {
            result[i] = buf.readUnsignedByte();
        }
        return result;
    }

    public static byte[] readBytes(ByteBuf buf, int len) {
        byte[] result = new byte[len];
        for(int i = 0; i < len; i++) {
            result[i] = buf.readByte();
        }
        return result;
    }

    public static String decodeBytesAsHex(ByteBuf byteBuf) {
        if (byteBuf.readableBytes() > 0) {
            byte[] bytes = new byte[byteBuf.readableBytes()];
            byteBuf.readBytes(bytes);
            return BaseEncoding.base16().encode(bytes);
        } else {
            return "";
        }
    }
}
