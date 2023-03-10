package org.easysocks.ssserver.obfs.entity;

import io.netty.buffer.ByteBuf;
import io.netty.buffer.Unpooled;
import lombok.Data;

@Data
public class HandshakeFinish {
    short contentType = 0x16;
    int version = 0x0303;
    int len;

    public static ByteBuf encode(HandshakeFinish content) {
        ByteBuf bf = Unpooled.buffer();
        bf.writeByte(content.getContentType());
        bf.writeShort(content.getVersion());
        bf.writeShort(content.getLen());
        return bf;
    }
}
