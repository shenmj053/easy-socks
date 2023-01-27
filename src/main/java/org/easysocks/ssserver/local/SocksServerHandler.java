package org.easysocks.ssserver.local;

import io.netty.buffer.Unpooled;
import io.netty.channel.ChannelFutureListener;
import io.netty.channel.ChannelHandlerContext;
import io.netty.channel.SimpleChannelInboundHandler;
import io.netty.handler.codec.socksx.SocksMessage;
import io.netty.handler.codec.socksx.SocksVersion;
import io.netty.handler.codec.socksx.v5.DefaultSocks5CommandResponse;
import io.netty.handler.codec.socksx.v5.DefaultSocks5InitialResponse;
import io.netty.handler.codec.socksx.v5.DefaultSocks5PasswordAuthResponse;
import io.netty.handler.codec.socksx.v5.Socks5AddressType;
import io.netty.handler.codec.socksx.v5.Socks5AuthMethod;
import io.netty.handler.codec.socksx.v5.Socks5CommandRequest;
import io.netty.handler.codec.socksx.v5.Socks5CommandRequestDecoder;
import io.netty.handler.codec.socksx.v5.Socks5CommandStatus;
import io.netty.handler.codec.socksx.v5.Socks5CommandType;
import io.netty.handler.codec.socksx.v5.Socks5InitialRequest;
import io.netty.handler.codec.socksx.v5.Socks5PasswordAuthRequest;
import io.netty.handler.codec.socksx.v5.Socks5PasswordAuthStatus;
import lombok.extern.slf4j.Slf4j;
import org.easysocks.ssserver.common.SsGlobalAttribute;

@Slf4j
public final class SocksServerHandler extends SimpleChannelInboundHandler<SocksMessage> {

    @Override
    public void channelRead0(ChannelHandlerContext ctx, SocksMessage socksRequest) {
        if (socksRequest.version() != SocksVersion.SOCKS5) {
            return;
        }
        if (socksRequest instanceof Socks5InitialRequest) {
            ctx.pipeline().addFirst(new Socks5CommandRequestDecoder());
            ctx.write(new DefaultSocks5InitialResponse(Socks5AuthMethod.NO_AUTH));
        } else if (socksRequest instanceof Socks5PasswordAuthRequest) {
            ctx.pipeline().addFirst(new Socks5CommandRequestDecoder());
            ctx.write(new DefaultSocks5PasswordAuthResponse(Socks5PasswordAuthStatus.SUCCESS));
        } else if (socksRequest instanceof Socks5CommandRequest) {
            Socks5CommandRequest socks5CmdRequest = (Socks5CommandRequest) socksRequest;
            if (socks5CmdRequest.type() == Socks5CommandType.CONNECT) {
                ctx.pipeline().remove(this);
                ctx.channel().writeAndFlush(new DefaultSocks5CommandResponse(
                        Socks5CommandStatus.SUCCESS,
                        Socks5AddressType.IPv4,
                        "0.0.0.0",
                        0));
                ctx.channel().attr(SsGlobalAttribute.REMOTE_DES_SOCKS5).set(socks5CmdRequest);
            } else {
                ctx.close();
            }
        } else {
            ctx.close();
        }
    }

    @Override
    public void channelReadComplete(ChannelHandlerContext ctx) {
        ctx.flush();
    }

    @Override
    public void exceptionCaught(ChannelHandlerContext ctx, Throwable throwable) {
        log.error(throwable.getMessage(), throwable);
        if (ctx.channel().isActive()) {
            ctx.channel().writeAndFlush(Unpooled.EMPTY_BUFFER).addListener(ChannelFutureListener.CLOSE);
        }
    }
}