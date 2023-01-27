package org.easysocks.ssserver.remote;

import io.netty.channel.ChannelHandlerContext;
import io.netty.channel.SimpleChannelInboundHandler;
import io.netty.channel.socket.DatagramPacket;
import java.net.InetSocketAddress;
import org.easysocks.ssserver.common.SsGlobalAttribute;

public class SsRemoteServerReceiverHandler extends SimpleChannelInboundHandler<Object> {

    public SsRemoteServerReceiverHandler() {
        super(false);
    }

    @Override
    protected void channelRead0(ChannelHandlerContext ctx, Object msg) {
        boolean isUdp = ctx.channel().attr(SsGlobalAttribute.IS_UDP).get();

        if (isUdp) {
            DatagramPacket udpRaw = ((DatagramPacket) msg);
            int miniUdpSize = 4;
            if (udpRaw.content().readableBytes() < miniUdpSize) {
                return;
            }
            ctx.channel().attr(SsGlobalAttribute.SS_CLIENT).set(udpRaw.sender());
            ctx.fireChannelRead(udpRaw.content());
        } else {
            ctx.channel().attr(SsGlobalAttribute.SS_CLIENT).set((InetSocketAddress) ctx.channel().remoteAddress());
            ctx.channel().pipeline().remove(this);
            ctx.fireChannelRead(msg);
        }
    }
}
