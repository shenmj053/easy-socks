package org.easysocks.ssserver.obfs.entity;

import lombok.Data;

@Data
public class TlsExtSessionTicket {
    int sessionTicketType = 0x0023;
    int sessionTicketExtLen;
    /**
     * session_ticket_ext_len
     */
    byte[] sessionTicket;
}
