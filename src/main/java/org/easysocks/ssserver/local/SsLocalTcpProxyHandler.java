package org.easysocks.ssserver.local;

import io.netty.bootstrap.Bootstrap;
import io.netty.buffer.ByteBuf;
import io.netty.buffer.Unpooled;
import io.netty.channel.*;
import io.netty.channel.socket.nio.NioSocketChannel;
import io.netty.handler.codec.socks.SocksAddressType;
import io.netty.handler.codec.socksx.v5.Socks5CommandRequest;
import io.netty.handler.timeout.IdleState;
import io.netty.handler.timeout.IdleStateEvent;
import io.netty.handler.timeout.IdleStateHandler;
import io.netty.util.ReferenceCountUtil;
import java.net.InetSocketAddress;
import java.util.ArrayList;
import java.util.List;
import java.util.Objects;
import java.util.concurrent.TimeUnit;
import lombok.extern.slf4j.Slf4j;
import org.easysocks.ssserver.cipher.AeadCipher;
import org.easysocks.ssserver.cipher.AeadCipherFactory;
import org.easysocks.ssserver.common.SsAddressRequest;
import org.easysocks.ssserver.codec.SsCipherCodec;
import org.easysocks.ssserver.common.SsGlobalAttribute;
import org.easysocks.ssserver.codec.SsProtocolCodec;
import org.easysocks.ssserver.config.SsConfig;
import org.easysocks.ssserver.obfs.HttpSimpleObfs;

@Slf4j
public class SsLocalTcpProxyHandler extends SimpleChannelInboundHandler<ByteBuf> {

    private final InetSocketAddress ssRemoteServer;
    private Socks5CommandRequest socks5CommandRequest;
    private Channel clientChannel;
    private Channel proxyChannel;
    private Bootstrap proxyClient;
    private List<ByteBuf> clientBuffs;
    private final SsConfig ssConfig;

    public SsLocalTcpProxyHandler(SsConfig ssConfig) {
        super(false);
        ssRemoteServer = new InetSocketAddress(ssConfig.getServerAddress(), ssConfig.getServerPort());
        this.ssConfig = ssConfig;
    }

    @Override
    protected void channelRead0(ChannelHandlerContext clientCtx, ByteBuf msg) {
        if (this.clientChannel == null) {
            this.clientChannel = clientCtx.channel();
            this.socks5CommandRequest = clientChannel.attr(SsGlobalAttribute.REMOTE_DES_SOCKS5).get();
        }
        log.info("client channel id {}, readableBytes: {}, proxy channel created: {}",
            clientChannel.id().toString(),
            msg.readableBytes(),
            proxyChannel != null);

        // First time connect to remote SS server.
        if (proxyChannel == null && proxyClient == null) {
            AeadCipher aeadCipher = AeadCipherFactory.create(ssConfig);
            proxyClient = new Bootstrap();
            proxyClient.group(clientChannel.eventLoop()).channel(NioSocketChannel.class)
                .option(ChannelOption.CONNECT_TIMEOUT_MILLIS, 60 * 1000)
                .option(ChannelOption.SO_KEEPALIVE, true)
                .option(ChannelOption.SO_RCVBUF, 32 * 2048)
                .option(ChannelOption.TCP_NODELAY, true)
                .handler(new ChannelInitializer<Channel>() {
                    @Override
                    protected void initChannel(Channel channel) throws Exception {
                        ChannelPipeline channelPipeline = channel.pipeline()
                            .addLast("timeout",
                                new IdleStateHandler(0, 0, 300, TimeUnit.SECONDS) {
                                    @Override
                                    protected IdleStateEvent newIdleStateEvent(IdleState state, boolean first) {
                                        proxyChannelClose();
                                        return super.newIdleStateEvent(state, first);
                                    }
                                }
                            );
                        if (Objects.equals(ssConfig.getObfs(), "http-simple")) {
                            channelPipeline.addLast("obfs", new HttpSimpleObfs(ssConfig, true));
                        }

                        channelPipeline.addLast("ssCipherCodec", new SsCipherCodec(aeadCipher))
                            .addLast("ssProtocolCodec", new SsProtocolCodec(true))
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
                    .connect(ssRemoteServer)
                    .addListener((ChannelFutureListener) future -> {
                        try {
                            if (future.isSuccess()) {
                                log.info("channel id {}, {} <-> {} <-> {} connected: {}",
                                    clientChannel.id().toString(),
                                    clientChannel.remoteAddress().toString(),
                                    future.channel().localAddress().toString(),
                                    ssRemoteServer.toString(),
                                    true);
                                proxyChannel = future.channel();

                                // write ss address to remote ss server, tell which website the client want to connect.
                                SsAddressRequest ssAddressRequest = new SsAddressRequest(
                                    SocksAddressType.valueOf(this.socks5CommandRequest.dstAddrType().byteValue()),
                                    this.socks5CommandRequest.dstAddr(),
                                    this.socks5CommandRequest.dstPort());

                                ByteBuf ssAddressBuff = Unpooled.buffer(128);
                                ssAddressRequest.encodeAsByteBuf(ssAddressBuff);
                                proxyChannel.writeAndFlush(ssAddressBuff);

                                //write remaining buffs to remote ss server after connecting successfully.
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
                                    ssRemoteServer.toString(),
                                    false,
                                    future.cause());
                                proxyChannelClose();
                            }
                        } catch (Exception e) {
                            proxyChannelClose();
                        }
                    });
            } catch (Exception e) {
                log.error("connect internet error", e);
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