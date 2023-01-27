package org.easysocks.ssserver.local;

import io.netty.bootstrap.ServerBootstrap;
import io.netty.channel.*;
import io.netty.channel.nio.NioEventLoopGroup;
import io.netty.channel.socket.nio.NioServerSocketChannel;
import io.netty.channel.socket.nio.NioSocketChannel;
import io.netty.handler.codec.socksx.SocksPortUnificationServerHandler;
import io.netty.handler.timeout.IdleState;
import io.netty.handler.timeout.IdleStateEvent;
import io.netty.handler.timeout.IdleStateHandler;
import java.util.concurrent.TimeUnit;
import lombok.extern.slf4j.Slf4j;
import org.easysocks.ssserver.SsServer;
import org.easysocks.ssserver.config.Config;
import org.easysocks.ssserver.config.ConfigReader;

@Slf4j
public class SsLocalClient implements SsServer {
    private static final EventLoopGroup bossGroup = new NioEventLoopGroup(1);
    private static final EventLoopGroup workerGroup = new NioEventLoopGroup();

    private final String localSocks5Server;
    private final int localSocks5Port;
    private final String remoteSocks5server;
    private final int remoteSocks5Port;
    private final String cipherName;
    private final String cipherPassword;

    public SsLocalClient(Config config) {
        localSocks5Server = "0.0.0.0";
        localSocks5Port = config.getClientPort();
        remoteSocks5server = config.getServerAddress();
        remoteSocks5Port = config.getServerPort();
        cipherName = config.getMethod();
        cipherPassword = config.getPassword();
    }

    public void start() throws Exception {
        ServerBootstrap tcpBootstrap = new ServerBootstrap();
        tcpBootstrap.group(bossGroup, workerGroup).channel(NioServerSocketChannel.class)
            .option(ChannelOption.SO_RCVBUF, 32 * 1024)
            .childOption(ChannelOption.SO_KEEPALIVE, true)
            .childHandler(new ChannelInitializer<NioSocketChannel>() {
                @Override
                protected void initChannel(NioSocketChannel ch) throws Exception {
                    ch.pipeline()
                        .addLast("timeout", new IdleStateHandler(0, 0, 120, TimeUnit.SECONDS) {
                            @Override
                            protected IdleStateEvent newIdleStateEvent(IdleState state, boolean first) {
                                ch.close();
                                return super.newIdleStateEvent(state, first);
                            }
                        })
                        .addLast(new SocksPortUnificationServerHandler())
                        .addLast(new SocksServerHandler())
                        .addLast(new SsLocalTcpProxyHandler(
                            remoteSocks5server, remoteSocks5Port,
                            cipherName, cipherPassword
                        ));
                }
            });

        tcpBootstrap.bind(localSocks5Server, localSocks5Port).sync();

        log.info("SS local server listen at {}: {}", localSocks5Server, localSocks5Port);
    }

    public void stop() {
        if (bossGroup != null) {
            bossGroup.shutdownGracefully();
        }
        if (workerGroup != null) {
            workerGroup.shutdownGracefully();
        }
        log.info("Stop local server!");
    }

    public static void main(String[] args) {
        String configFile = "";
        if (args.length == 1) {
            configFile = args[0];
        }
        Config config = new ConfigReader().read(configFile);
        SsLocalClient server = new SsLocalClient(config);
        try {
            server.start();
        } catch (Exception e) {
            e.printStackTrace();
            server.stop();
            System.exit(1);
        }
    }

}
