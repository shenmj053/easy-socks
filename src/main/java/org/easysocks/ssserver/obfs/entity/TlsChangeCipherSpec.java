package org.easysocks.ssserver.obfs.entity;

import io.netty.buffer.ByteBuf;
import io.netty.buffer.Unpooled;
import lombok.Data;

@Data
public class TlsChangeCipherSpec {
    short contentType = 0x14;
    int version = 0x0303;
    int len = 0x0001;
    short msg = 0x01;

    public static ByteBuf encode(TlsChangeCipherSpec content) {
        ByteBuf bf = Unpooled.buffer();
        bf.writeByte(content.getContentType());
        bf.writeShort(content.getVersion());
        bf.writeShort(content.getLen());
        bf.writeByte(content.getMsg());
        return bf;
    }
}
