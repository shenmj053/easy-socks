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
            throw new Exception("unsupported msg type:" + msg.getClass());
        }

        byte[] encryptedBytes = encrypt(buf);

        if (encryptedBytes == null || encryptedBytes.length == 0) {
            return;
        }
        ByteBuf encryptedBuf = ctx.alloc().buffer(encryptedBytes.length);
        encryptedBuf.writeBytes(encryptedBytes);
        out.add(encryptedBuf);
    }

    @Override
    protected void decode(ChannelHandlerContext ctx, Object msg, List<Object> out) throws Exception {
        ByteBuf buf;
        if (msg instanceof DatagramPacket) {
            buf = ((DatagramPacket) msg).content();
        } else if (msg instanceof ByteBuf) {
            buf = (ByteBuf) msg;
        } else {
            throw new Exception("unsupported msg type:" + msg.getClass());
        }

        byte[] decryptedBytes = decrypt(buf);
        if (decryptedBytes.length == 0) {
            return;
        }
        ByteBuf decryptedBuf = ctx.alloc().buffer(decryptedBytes.length);
        decryptedBuf.writeBytes(decryptedBytes);
        out.add(decryptedBuf);
    }

    private byte[] encrypt(ByteBuf buf) {
        byte[] srcBytes = new byte[buf.readableBytes()];
        buf.getBytes(0, srcBytes);
        try {
            return aeadCipher.encrypt(srcBytes);
        } catch (Exception e) {
            log.error("Failed to encrypt bytes, ", e);
            return new byte[]{};
        }
    }

    private byte[] decrypt(ByteBuf buf) {
        byte[] srcBytes = new byte[buf.readableBytes()];
        buf.getBytes(0, srcBytes);
        try {
            return aeadCipher.decrypt(srcBytes);
        } catch (Exception e) {
            log.error("Failed to decrypt bytes, ", e);
            return new byte[]{};
        }
    }
}
