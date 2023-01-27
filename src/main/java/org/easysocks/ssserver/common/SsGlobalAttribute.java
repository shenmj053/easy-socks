package org.easysocks.ssserver.common;

import io.netty.handler.codec.socksx.v5.Socks5CommandRequest;
import io.netty.util.AttributeKey;
import java.net.InetSocketAddress;

public class SsGlobalAttribute {
    public static final AttributeKey<Boolean> IS_UDP = AttributeKey.valueOf("ss_is_udp");
    public static final AttributeKey<InetSocketAddress> SS_CLIENT = AttributeKey.valueOf("ss_client");
    public static final AttributeKey<InetSocketAddress> REMOTE_DES = AttributeKey.valueOf("ss_remote_des");
    public static final AttributeKey<Socks5CommandRequest> REMOTE_DES_SOCKS5 = AttributeKey.valueOf("remote_des_socks5");
}
