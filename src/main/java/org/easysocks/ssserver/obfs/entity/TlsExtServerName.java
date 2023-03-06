package org.easysocks.ssserver.obfs.entity;

import lombok.Data;

@Data
public class TlsExtServerName {
    int extType;
    int extLen;
    int serverNameListLen;
    short serverNameType;
    int serverNameLen;
    /**
     * serverNameLen
     */
    short[] serverName;
}
