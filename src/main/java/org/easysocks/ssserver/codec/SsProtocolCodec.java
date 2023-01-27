package org.easysocks.ssserver.codec;

import static org.easysocks.ssserver.common.SsGlobalAttribute.SS_CLIENT;
import io.netty.buffer.ByteBuf;
import io.netty.buffer.Unpooled;
import io.netty.channel.ChannelHandlerContext;
import io.netty.handler.codec.MessageToMessageCodec;
import io.netty.handler.codec.socks.SocksAddressType;
import java.net.Inet4Address;
import java.net.Inet6Address;
import java.net.InetSocketAddress;
import java.util.List;
import lombok.extern.slf4j.Slf4j;
import org.easysocks.ssserver.common.SsAddressRequest;
import org.easysocks.ssserver.common.SsGlobalAttribute;

/**
 * <a href="http://shadowsocks.org/guide/what-is-shadowsocks.html">shadowsocks doc</a>
 * [1-byte type][variable-length host][2-byte port]
 * The following address types are defined:
 * <p>
 * 0x01: host is a 4-byte IPv4 address.
 * 0x03: host is a variable length string, starting with a 1-byte length, followed by up to 255-byte domain name.
 * 0x04: host is a 16-byte IPv6 address.
 * The port number is a 2-byte big-endian unsigned integer.
 **/
@Slf4j
public class SsProtocolCodec extends MessageToMessageCodec<Object, Object> {
    private boolean ssClient;
    private boolean tcpAddressSet = false;

    public SsProtocolCodec() {
        this(false);
    }

    public SsProtocolCodec(boolean ssClient) {
        super();
        this.ssClient = ssClient;
    }

    @Override
    protected void encode(ChannelHandlerContext ctx, Object msg, List<Object> out) throws Exception {
        ByteBuf buf;
        if (msg instanceof ByteBuf) {
            buf = (ByteBuf) msg;
        } else {
            throw new Exception("unsupported msg type:" + msg.getClass());
        }

        // target address: [1-byte type][variable-length host][2-byte port]
        // udp: [target address][payload]
        // tcp: [payload]

        InetSocketAddress inetSocketAddress = null;
        if (ssClient && !tcpAddressSet) {
            inetSocketAddress = ctx.channel().attr(SsGlobalAttribute.REMOTE_DES).get();
            tcpAddressSet = true;
        }

        if (inetSocketAddress == null) {
            buf.retain();
        } else {
            SsAddressRequest ssAddressRequest;

            if (inetSocketAddress.getAddress() instanceof Inet6Address) {
                ssAddressRequest = new SsAddressRequest(
                    SocksAddressType.IPv6,
                    inetSocketAddress.getHostString(),
                    inetSocketAddress.getPort()
                );
            } else if (inetSocketAddress.getAddress() instanceof Inet4Address) {
                ssAddressRequest = new SsAddressRequest(
                    SocksAddressType.IPv4,
                    inetSocketAddress.getHostString(),
                    inetSocketAddress.getPort()
                );
            } else {
                ssAddressRequest = new SsAddressRequest(
                    SocksAddressType.DOMAIN,
                    inetSocketAddress.getHostString(),
                    inetSocketAddress.getPort()
                );
            }

            ByteBuf addrBuff = Unpooled.buffer(128);
            ssAddressRequest.encodeAsByteBuf(addrBuff);

            buf = Unpooled.wrappedBuffer(addrBuff, buf.retain());
        }

        msg = buf;
        out.add(msg);
    }

    @Override
    protected void decode(ChannelHandlerContext ctx, Object msg, List<Object> out) throws Exception {
        ByteBuf buf;
        if (msg instanceof ByteBuf) {
            buf = (ByteBuf) msg;
        } else {
            throw new Exception("unsupported msg type:" + msg.getClass());
        }

        // [1-byte type][variable-length host][2-byte port]
        if (buf.readableBytes() < 1 + 1 + 2) {
            return;
        }

        InetSocketAddress addr;
        // if the server is ss remote and tcpAddressed is not set.
        if (!ssClient && !tcpAddressSet) {
            // after get ss address request from buff, read index of buff is changed.
            SsAddressRequest addressRequest = SsAddressRequest.getSsAddressRequest(buf);
            if (addressRequest == null) {
                return;
            }
            addr = new InetSocketAddress(addressRequest.host(), addressRequest.port());

            ctx.channel().attr(SsGlobalAttribute.REMOTE_DES).set(addr);

            tcpAddressSet = true;
        }
        buf.retain();
        out.add(msg);
    }

    @Override
    public void exceptionCaught(ChannelHandlerContext ctx, Throwable cause) {
        InetSocketAddress clientSender = ctx.channel().attr(SS_CLIENT).get();
        log.error(String.format("client %s", clientSender.toString()), cause);
    }
}