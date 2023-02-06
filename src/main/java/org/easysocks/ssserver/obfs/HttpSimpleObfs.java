package org.easysocks.ssserver.obfs;

import com.google.common.primitives.Bytes;
import io.netty.buffer.ByteBuf;
import io.netty.buffer.Unpooled;
import io.netty.channel.ChannelHandlerContext;
import io.netty.handler.codec.MessageToMessageCodec;
import java.util.List;
import org.easysocks.ssserver.config.SsConfig;

public class HttpSimpleObfs extends MessageToMessageCodec<Object, Object> {
    private final boolean ssClient;
    private final SsConfig ssConfig;
    private boolean hasSentHeader = false;
    private boolean hasReceivedHeader = false;
    private final ByteBuf receiveBuffer = Unpooled.buffer(65535);

    public HttpSimpleObfs(SsConfig ssConfig, boolean ssClient) {
        this.ssConfig = ssConfig;
        this.ssClient = ssClient;
    }

    @Override
    protected void encode(ChannelHandlerContext ctx, Object msg, List<Object> out) {
        ByteBuf buf = (ByteBuf) msg;
        ByteBuf encodedBuf;
        if (ssClient) {
            encodedBuf = clientEncode(buf);
        } else {
            encodedBuf = serverEncode(buf);
        }
        out.add(encodedBuf);
    }

    @Override
    protected void decode(ChannelHandlerContext ctx, Object msg, List<Object> out) {
        ByteBuf buf = (ByteBuf) msg;
        ByteBuf decodedBuf;
        if (ssClient) {
            decodedBuf = clientDecode(buf);
        } else {
            decodedBuf = serverDecode(buf);
        }
        if (decodedBuf.readableBytes() > 0) {
            out.add(decodedBuf);
        }
    }

    private ByteBuf clientEncode(ByteBuf buf) {
        if (hasSentHeader) {
            buf.retain();
            return buf;
        }
        ByteBuf httpHeadBuf = Unpooled.buffer();
        httpHeadBuf.writeBytes("GET / ".getBytes());
        httpHeadBuf.writeBytes("HTTP/1.1\r\n".getBytes());
        httpHeadBuf.writeBytes(("Host: " + ssConfig.getMockServerName() + "\r\n").getBytes());
        String userAgent = "User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/108.0.0.0 Safari/537.36\r\n";
        httpHeadBuf.writeBytes(userAgent.getBytes());
        httpHeadBuf.writeBytes("Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8\r\n".getBytes());
        httpHeadBuf.writeBytes("Accept-Language: en-US,en;q=0.8\r\n".getBytes());
        httpHeadBuf.writeBytes("Accept-Encoding: gzip, deflate\r\n".getBytes());
        httpHeadBuf.writeBytes("Connection: keep-alive\r\n\r\n".getBytes());
        ByteBuf resultBuf = Unpooled.buffer(httpHeadBuf.readableBytes() + buf.readableBytes());
        resultBuf.writeBytes(httpHeadBuf);
        resultBuf.writeBytes(buf);
        hasSentHeader = true;
        return resultBuf;
    }

    private ByteBuf clientDecode(ByteBuf buf) {
        if (hasReceivedHeader) {
            buf.retain();
            return buf;
        }

        receiveBuffer.writeBytes(buf);
        byte[] receiveBufferArray = new byte[receiveBuffer.readableBytes()];
        receiveBuffer.readBytes(receiveBufferArray);
        receiveBuffer.resetReaderIndex();
        int index = Bytes.indexOf(receiveBufferArray, "\r\n\r\n".getBytes());
        if (index >= 0) {
            ByteBuf desBuf = Unpooled.buffer(receiveBufferArray.length - index - 4);
            desBuf.writeBytes(receiveBuffer, index + 4, receiveBufferArray.length - index - 4);
            hasReceivedHeader = true;
            receiveBuffer.clear();
            return desBuf;
        }
        return Unpooled.buffer(0);
    }

    private ByteBuf serverEncode(ByteBuf buf) {
        if (hasSentHeader) {
            buf.retain();
            return buf;
        }
        ByteBuf httpHeadBuf = Unpooled.buffer();
        httpHeadBuf.writeBytes("HTTP/1.1 200 OK\r\n".getBytes());
        httpHeadBuf.writeBytes("Connection: keep-alive\r\n".getBytes());
        httpHeadBuf.writeBytes("Content-Encoding: gzip\r\n".getBytes());
        httpHeadBuf.writeBytes("Content-Type: text/html\r\n".getBytes());
        httpHeadBuf.writeBytes("Server: nginx\r\n".getBytes());
        httpHeadBuf.writeBytes("Vary: Accept-Encoding\r\n\r\n".getBytes());
        ByteBuf resultBuf = Unpooled.buffer(httpHeadBuf.readableBytes() + buf.readableBytes());
        resultBuf.writeBytes(httpHeadBuf);
        resultBuf.writeBytes(buf);
        hasSentHeader = true;
        return resultBuf;
    }

    private ByteBuf serverDecode(ByteBuf buf) {
        if (hasReceivedHeader) {
            buf.retain();
            return buf;
        }
        receiveBuffer.writeBytes(buf);
        byte[] receiveBufferArray = new byte[receiveBuffer.readableBytes()];
        receiveBuffer.readBytes(receiveBufferArray);
        receiveBuffer.resetReaderIndex();
        int index = Bytes.indexOf(receiveBufferArray, "\r\n\r\n".getBytes());
        if (index >= 0) {
            ByteBuf desBuf = Unpooled.buffer(receiveBufferArray.length - index - 4);
            desBuf.writeBytes(receiveBuffer, index + 4, receiveBufferArray.length - index - 4);
            hasReceivedHeader = true;
            receiveBuffer.clear();
            return desBuf;
        }
        return Unpooled.buffer(0);
    }

    public static void main(String[] args) {
        ByteBuf desBuf = Unpooled.buffer();
        desBuf.writeBytes("afsfasfsdfsafa".getBytes());
        desBuf.readableBytes();
        desBuf.clear();
    }
}
