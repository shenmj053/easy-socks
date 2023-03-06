package org.easysocks.ssserver.obfs.entity;

import io.netty.buffer.ByteBuf;
import io.netty.buffer.Unpooled;
import lombok.Data;

@Data
public class TlsExtSessionTicket {
    int sessionTicketType = 0x0023;
    int sessionTicketExtLen;
    /**
     * session_ticket_ext_len
     */
    byte[] sessionTicket;

    public static ByteBuf encode(TlsExtSessionTicket content) {
        ByteBuf bf = Unpooled.buffer();
        bf.writeShort(content.getSessionTicketType());
        bf.writeShort(content.getSessionTicketExtLen());
        bf.writeBytes(content.getSessionTicket());
        return bf;
    }
}
