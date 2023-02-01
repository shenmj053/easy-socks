package org.easysocks.ssserver.remote;

import io.netty.bootstrap.ServerBootstrap;
import io.netty.channel.ChannelFuture;
import io.netty.channel.ChannelInitializer;
import io.netty.channel.ChannelOption;
import io.netty.channel.EventLoopGroup;
import io.netty.channel.nio.NioEventLoopGroup;
import io.netty.channel.socket.nio.NioServerSocketChannel;
import io.netty.channel.socket.nio.NioSocketChannel;
import io.netty.handler.timeout.IdleState;
import io.netty.handler.timeout.IdleStateEvent;
import io.netty.handler.timeout.IdleStateHandler;
import java.util.concurrent.TimeUnit;
import lombok.extern.slf4j.Slf4j;
import org.easysocks.ssserver.SsServer;
import org.easysocks.ssserver.cipher.AeadCipher;
import org.easysocks.ssserver.cipher.AeadCipherFactory;
import org.easysocks.ssserver.codec.SsCipherCodec;
import org.easysocks.ssserver.common.SsGlobalAttribute;
import org.easysocks.ssserver.codec.SsProtocolCodec;
import org.easysocks.ssserver.config.SsConfig;

@Slf4j
public class SsRemoteServer implements SsServer {
    private static final EventLoopGroup bossGroup = new NioEventLoopGroup(1);
    private static final EventLoopGroup workerGroup = new NioEventLoopGroup();
    private final SsConfig ssConfig;

    public SsRemoteServer(SsConfig ssConfig) {
        this.ssConfig = ssConfig;
    }

    public void start() throws Exception {
        try {
            ServerBootstrap tcpBootstrap = new ServerBootstrap();
            tcpBootstrap.group(bossGroup, workerGroup).channel(NioServerSocketChannel.class)
                .option(ChannelOption.SO_BACKLOG, 5120)
                .option(ChannelOption.SO_RCVBUF, 32 * 1024)
                .childOption(ChannelOption.SO_KEEPALIVE, true)
                .childOption(ChannelOption.TCP_NODELAY, false)
                .childOption(ChannelOption.SO_LINGER, 1)
                .childHandler(new ChannelInitializer<NioSocketChannel>() {
                    @Override
                    protected void initChannel(NioSocketChannel ch) throws Exception {
                        AeadCipher aeadCipher = AeadCipherFactory.create(ssConfig);
                        ch.attr(SsGlobalAttribute.IS_UDP).set(false);
                        ch.pipeline()
                            .addLast("timeout", new IdleStateHandler(0, 0, 300, TimeUnit.SECONDS) {
                                @Override
                                protected IdleStateEvent newIdleStateEvent(IdleState state, boolean first) {
                                    ch.close();
                                    return super.newIdleStateEvent(state, first);
                                }
                            })
                            //ss message received from client
                            .addLast(new SsRemoteServerReceiverHandler())
                            //ss message send to client
                            .addLast(new SsRemoteServerSenderHandler())
                            //ss-cypt
                            .addLast("ssCipherCodec", new SsCipherCodec(aeadCipher))
                            //ss-protocol
                            .addLast(new SsProtocolCodec())
                            //ss-proxy
                            .addLast("ssTcpProxy", new SsRemoteTcpProxyHandler())
                        ;
                    }
                });
            log.info("SS remote server listen at {}: {}",
                ssConfig.getServerAddress(),
                ssConfig.getServerPort());
            ChannelFuture f = tcpBootstrap.bind(
                ssConfig.getServerAddress(),
                ssConfig.getServerPort())
                .sync();
            f.channel().closeFuture().sync();
        } finally {
            log.info("Stop remote server!");
            bossGroup.shutdownGracefully().sync();
            workerGroup.shutdownGracefully().sync();
            log.info("Stop remote server!");
        }
    }
}
