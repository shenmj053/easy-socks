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
public class TlsExtSessionTicket {
    public static int byteLength = 4;
    int sessionTicketType = 0x0023;
    int sessionTicketExtLen;
//    byte[] sessionTicket;

    public static ByteBuf encode(TlsExtSessionTicket content) {
        ByteBuf bf = Unpooled.buffer();
        bf.writeShort(content.getSessionTicketType());
        bf.writeShort(content.getSessionTicketExtLen());
        return bf;
    }

    public static TlsExtSessionTicket decode(ByteBuf buf) {
        return TlsExtSessionTicket
            .builder()
            .sessionTicketType(buf.readUnsignedShort())
            .sessionTicketExtLen(buf.readUnsignedShort())
            .build();
    }
}
