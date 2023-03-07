package org.easysocks.ssserver.obfs.entity;

import io.netty.buffer.ByteBuf;
import io.netty.buffer.Unpooled;
import lombok.Data;

@Data
public class TlsEncryptedHandshake {
    short contentType = 0x16;
    int version = 0x0303;
    int len = 64;
//    short[] msg = new short[len];
    public static ByteBuf encode(TlsEncryptedHandshake content) {
        ByteBuf bf = Unpooled.buffer();
        bf.writeByte(content.getContentType());
        bf.writeShort(content.getVersion());
        bf.writeShort(content.getLen());
        return bf;
    }
}
