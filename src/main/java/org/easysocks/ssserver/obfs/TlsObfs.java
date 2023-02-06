package org.easysocks.ssserver.obfs;

import io.netty.channel.ChannelHandlerContext;
import io.netty.handler.codec.MessageToMessageCodec;
import java.util.List;

public class TlsObfs extends MessageToMessageCodec<Object, Object> {

    @Override
    protected void encode(ChannelHandlerContext ctx, Object msg, List<Object> out)
        throws Exception {

    }

    @Override
    protected void decode(ChannelHandlerContext ctx, Object msg, List<Object> out)
        throws Exception {

    }
}
