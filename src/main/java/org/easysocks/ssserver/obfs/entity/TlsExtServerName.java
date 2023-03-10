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
public class TlsExtServerName {
    public static int byteLength = 9;

    int extType = 0x0000;
    int extLen;
    int serverNameListLen;
    short serverNameType = 0x00;
    int serverNameLen;
//    byte[] serverName;

    public static ByteBuf encode(TlsExtServerName content) {
        ByteBuf bf = Unpooled.buffer();
        bf.writeShort(content.getExtType());
        bf.writeShort(content.getExtLen());
        bf.writeShort(content.getServerNameListLen());
        bf.writeByte(content.getServerNameType());
        bf.writeShort(content.getServerNameLen());
        return bf;
    }

    public static TlsExtServerName decode(ByteBuf buf) {
        return TlsExtServerName
            .builder()
            .extType(buf.readUnsignedShort())
            .extLen(buf.readUnsignedShort())
            .serverNameListLen(buf.readUnsignedShort())
            .serverNameType(buf.readUnsignedByte())
            .serverNameLen(buf.readUnsignedShort())
            .build();
    }
}
