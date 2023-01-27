package org.easysocks.ssserver.remote;

import io.netty.bootstrap.Bootstrap;
import io.netty.buffer.ByteBuf;
import io.netty.channel.*;
import io.netty.channel.socket.nio.NioSocketChannel;
import io.netty.handler.timeout.IdleState;
import io.netty.handler.timeout.IdleStateEvent;
import io.netty.handler.timeout.IdleStateHandler;
import io.netty.util.ReferenceCountUtil;
import java.net.InetSocketAddress;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.TimeUnit;
import lombok.extern.slf4j.Slf4j;
import org.easysocks.ssserver.common.SsGlobalAttribute;

@Slf4j
public class SsRemoteTcpProxyHandler extends SimpleChannelInboundHandler<ByteBuf> {

    private Channel clientChannel;
    private Channel proxyChannel;
    private Bootstrap proxyClient;
    private List<ByteBuf> clientBuffs;

    public SsRemoteTcpProxyHandler() {
        super(false);
    }


    @Override
    protected void channelRead0(ChannelHandlerContext clientCtx, ByteBuf msg) throws Exception {
        if (this.clientChannel == null) {
            this.clientChannel = clientCtx.channel();
        }
        log.info("client channel id {}, readableBytes: {}, proxy channel created: {}",
            clientChannel.id().toString(),
            msg.readableBytes(),
            proxyChannel != null);

        if (proxyChannel == null && proxyClient == null) {
            proxyClient = new Bootstrap();
            InetSocketAddress remoteDesAddress = clientChannel.attr(SsGlobalAttribute.REMOTE_DES).get();

            proxyClient.group(clientChannel.eventLoop()).channel(NioSocketChannel.class)
                .option(ChannelOption.CONNECT_TIMEOUT_MILLIS, 60 * 1000)
                .option(ChannelOption.SO_KEEPALIVE, true)
                .option(ChannelOption.SO_RCVBUF, 32 * 1024)
                .option(ChannelOption.TCP_NODELAY, true)
                .handler(
                    new ChannelInitializer<Channel>() {
                        @Override
                        protected void initChannel(Channel ch) throws Exception {
                            ch.pipeline()
                                .addLast("timeout", new IdleStateHandler(0, 0, 120, TimeUnit.SECONDS) {
                                    @Override
                                    protected IdleStateEvent newIdleStateEvent(IdleState state, boolean first) {
                                        log.info("{} state:{}", remoteDesAddress.toString(), state.toString());
                                        proxyChannelClose();
                                        return super.newIdleStateEvent(state, first);
                                    }
                                })
                                .addLast("relay", new SimpleChannelInboundHandler<ByteBuf>(false) {
                                    @Override
                                    protected void channelRead0(ChannelHandlerContext ctx, ByteBuf msg) throws Exception {
                                        clientChannel.writeAndFlush(msg);
                                    }

                                    @Override
                                    public void channelActive(ChannelHandlerContext ctx) {
                                    }

                                    @Override
                                    public void channelInactive(ChannelHandlerContext ctx) throws Exception {
                                        super.channelInactive(ctx);
                                        proxyChannelClose();
                                    }

                                    @Override
                                    public void exceptionCaught(ChannelHandlerContext ctx, Throwable cause) throws Exception {
                                        proxyChannelClose();
                                    }
                                });
                        }
                    }
                );
            try {
                proxyClient
                    .connect(remoteDesAddress)
                    .addListener((ChannelFutureListener) future -> {
                        try {
                            if (future.isSuccess()) {
                                log.info("channel id {}, {} <-> {} <-> {} connected: {}",
                                    clientChannel.id().toString(),
                                    clientChannel.remoteAddress().toString(),
                                    future.channel().localAddress().toString(),
                                    remoteDesAddress.toString(),
                                    true);
                                proxyChannel = future.channel();
                                if (clientBuffs != null) {
                                    for (ByteBuf clientBuff : clientBuffs) {
                                        proxyChannel.writeAndFlush(clientBuff);
                                    }
                                    clientBuffs = null;
                                }
                            } else {
                                log.error("channel id {}, {} <-> {} connected: {}, cause: {}",
                                    clientChannel.id().toString(),
                                    clientChannel.remoteAddress().toString(),
                                    remoteDesAddress.toString(),
                                    false,
                                    future.cause());
                                proxyChannelClose();
                            }
                        } catch (Exception e) {
                            proxyChannelClose();
                        }
                    });
            } catch (Exception e) {
                log.error("Connect to internet error", e);
                proxyChannelClose();
                return;
            }
        }

        // proxyClient connect is async, proxyChannel could be not created yet at this time.
        if (proxyChannel == null) {
            if (clientBuffs == null) {
                clientBuffs = new ArrayList<>();
            }
            clientBuffs.add(msg);
            log.info("client channel id: {}, add ByteBuf message [{} Bytes] to client buff list.",
                clientChannel.id().toString(),
                msg.readableBytes());
        } else {
            if (clientBuffs == null) {
                proxyChannel.writeAndFlush(msg);
                log.info("proxy channel id: {}, proxy channel write [{} Bytes].",
                    proxyChannel.id().toString(),
                    msg.readableBytes());
            } else {
                clientBuffs.add(msg);
                log.info("proxy channel id: {}, add ByteBuf message [{} Bytes] to client buff list.",
                    proxyChannel.id().toString(),
                    msg.readableBytes());
            }
        }
    }


    @Override
    public void channelInactive(ChannelHandlerContext ctx) throws Exception {
        super.channelInactive(ctx);
        proxyChannelClose();
    }

    @Override
    public void exceptionCaught(ChannelHandlerContext ctx, Throwable cause) throws Exception {
        super.exceptionCaught(ctx,cause);
        proxyChannelClose();
    }

    private void proxyChannelClose() {
        try {
            if (clientBuffs != null) {
                clientBuffs.forEach(ReferenceCountUtil::release);
                clientBuffs = null;
            }
            if (proxyChannel != null) {
                proxyChannel.close();
                proxyChannel = null;
            }
            if (clientChannel != null) {
                clientChannel.close();
                clientChannel = null;
            }
        } catch (Exception e) {
            log.error("close channel error", e);
        }
    }
}