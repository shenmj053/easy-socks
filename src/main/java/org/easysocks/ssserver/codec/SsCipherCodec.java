package org.easysocks.ssserver.codec;

import io.netty.buffer.ByteBuf;
import io.netty.channel.ChannelHandlerContext;
import io.netty.channel.socket.DatagramPacket;
import io.netty.handler.codec.MessageToMessageCodec;
import java.util.List;
import lombok.extern.slf4j.Slf4j;
import org.easysocks.ssserver.cipher.AeadCipher;

@Slf4j
public class SsCipherCodec extends MessageToMessageCodec<Object, Object> {
    private final AeadCipher aeadCipher;

    public SsCipherCodec(AeadCipher aeadCipher) {
        this.aeadCipher = aeadCipher;
    }

    @Override
    protected void encode(ChannelHandlerContext ctx, Object msg, List<Object> out) throws Exception {
        ByteBuf buf;
        if (msg instanceof DatagramPacket) {
            buf = ((DatagramPacket) msg).content();
        } else if (msg instanceof ByteBuf) {
            buf = (ByteBuf) msg;
        } else {
            throw new Exception("Encode error, unsupported msg type:" + msg.getClass());
        }
        try {
            ByteBuf encryptedByteBuf = aeadCipher.encrypt(buf);
            if (encryptedByteBuf.readableBytes() > 0) {
                out.add(encryptedByteBuf);
            }
        } catch (Exception e) {
            log.error("Failed to encrypt bytes, ", e);
        }
    }

    @Override
    protected void decode(ChannelHandlerContext ctx, Object msg, List<Object> out) throws Exception {
        ByteBuf buf;
        if (msg instanceof DatagramPacket) {
            buf = ((DatagramPacket) msg).content();
        } else if (msg instanceof ByteBuf) {
            buf = (ByteBuf) msg;
        } else {
            throw new Exception("Decode error, unsupported msg type:" + msg.getClass());
        }

        try {
            ByteBuf decryptedByteBuf = aeadCipher.decrypt(buf);
            if (decryptedByteBuf.readableBytes() > 0) {
                out.add(decryptedByteBuf);
            }
        } catch (Exception e) {
            log.error("Failed to decrypt bytes, ", e);
        }
    }
}
