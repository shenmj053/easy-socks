package org.easysocks.ssserver.remote;

import io.netty.buffer.ByteBuf;
import io.netty.channel.ChannelHandlerContext;
import io.netty.channel.ChannelOutboundHandlerAdapter;
import io.netty.channel.ChannelPromise;
import io.netty.channel.socket.DatagramPacket;
import java.net.InetSocketAddress;
import lombok.extern.slf4j.Slf4j;
import org.easysocks.ssserver.common.SsGlobalAttribute;

@Slf4j
public class SsRemoteServerSenderHandler extends ChannelOutboundHandlerAdapter {

    @Override
    public void write(ChannelHandlerContext ctx, Object msg, ChannelPromise promise) throws Exception {
        boolean isUdp = ctx.channel().attr(SsGlobalAttribute.IS_UDP).get();
        if (isUdp) {
            InetSocketAddress client = ctx.channel().attr(SsGlobalAttribute.SS_CLIENT).get();
            msg = new DatagramPacket((ByteBuf) msg, client);
        }
        log.info("encoded msg send to client, size:" + ((ByteBuf) msg).readableBytes());
        super.write(ctx, msg, promise);
    }
}