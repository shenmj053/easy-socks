package org.easysocks.ssserver.obfs.entity;

import io.netty.buffer.ByteBuf;
import io.netty.buffer.Unpooled;
import lombok.Data;

@Data
public class TlsExtServerName {
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
}
