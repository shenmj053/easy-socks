package org.easysocks.ssserver.obfs.entity;

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
public class TlsChangeCipherSpec {
    public static int byteLength = 6;

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

    public static TlsChangeCipherSpec decode(ByteBuf buf) {
        return TlsChangeCipherSpec
            .builder()
            .contentType(buf.readUnsignedByte())
            .version(buf.readUnsignedShort())
            .len(buf.readUnsignedShort())
            .msg(buf.readUnsignedByte())
            .build();
    }
}
