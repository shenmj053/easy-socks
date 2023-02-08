package org.easysocks.ssserver.obfs;

import com.google.common.primitives.Bytes;
import io.netty.buffer.ByteBuf;
import io.netty.buffer.Unpooled;
import io.netty.channel.ChannelHandlerContext;
import io.netty.handler.codec.MessageToMessageCodec;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.time.LocalDateTime;
import java.time.ZoneOffset;
import java.util.Arrays;
import java.util.List;
import java.util.Map;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import org.easysocks.ssserver.config.SsConfig;

public class TlsObfs extends MessageToMessageCodec<Object, Object> {
    /**
     * enum {
     *        hello_request(0), client_hello(1), server_hello(2),
     *        certificate(11), server_key_exchange (12),
     *        certificate_request(13), server_hello_done(14),
     *        certificate_verify(15), client_key_exchange(16),
     *        finished(20)
     *        (255)
     *    } HandshakeType;
     */
    private static byte[] TLS_VERSION = {0x03, 0x03};
    private static byte[] TLS_AES_128_GCM_SHA256 = {0x13, 0x01};
    private static byte[] CHANGE_CIPHER = {0x14};
    private static byte[] ALERT = {0x15};
    private static byte[] HANDSHAKE = {0x16};
    private static byte[] APPLICATION_DATA = {0x17};

    private final boolean ssClient;
    private final String clientId;
    private final SsConfig ssConfig;

    private int handshakeStatus = 0;
    private boolean hasSentHeader = false;
    private boolean hasReceivedHeader = false;
    private final ByteBuf receiveBuffer = Unpooled.buffer(65535);
    private final ByteBuf sendBuffer = Unpooled.buffer(65535);

    private Map<String, byte[]> ticketBufCache;

    public TlsObfs(SsConfig ssConfig, boolean ssClient, String clientId) {
        this.ssConfig = ssConfig;
        this.ssClient = ssClient;
        this.clientId = clientId;
    }

    @Override
    protected void encode(ChannelHandlerContext ctx, Object msg, List<Object> out)
        throws NoSuchAlgorithmException, InvalidKeyException {
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

    public static String hexlify(byte[] hash) {
        StringBuilder hexString = new StringBuilder(2 * hash.length);
        for (byte h : hash) {
            String hex = Integer.toHexString(0xff & h);
            if (hex.length() == 1) {
                hexString.append('0');
            }
            hexString.append(hex);
        }
        return hexString.toString();
    }

    public static byte[] unhexlify(String argbuf) {
        int arglen = argbuf.length();
        if (arglen % 2 != 0) {
            throw new RuntimeException("Odd-length string");
        }

        byte[] retbuf = new byte[arglen/2];

        for (int i = 0; i < arglen; i += 2) {
            int top = Character.digit(argbuf.charAt(i), 16);
            int bot = Character.digit(argbuf.charAt(i+1), 16);
            if (top == -1 || bot == -1) {
                throw new RuntimeException("Non-hexadecimal digit found");
            }
            retbuf[i / 2] = (byte) ((top << 4) + bot);
        }
        return retbuf;
    }

    private static byte[] hmacWithSha1(String algorithm, String data, String key)
        throws NoSuchAlgorithmException, InvalidKeyException {
        SecretKeySpec secretKeySpec = new SecretKeySpec(key.getBytes(), algorithm);
        Mac mac = Mac.getInstance(algorithm);
        mac.init(secretKeySpec);
        return mac.doFinal(data.getBytes());
    }


    private ByteBuf packAuthData(String clientId)
        throws NoSuchAlgorithmException, InvalidKeyException {
        ByteBuf packAuthBuf = Unpooled.buffer();
        long epochSecond = LocalDateTime.now().toEpochSecond(ZoneOffset.UTC);
        packAuthBuf.writeInt((int)epochSecond);
        byte[] randomBytes = new byte[18];
        SecureRandom.getInstanceStrong().nextBytes(randomBytes);
        packAuthBuf.writeBytes(randomBytes);
        byte[] result = hmacWithSha1("HmacSHA1", packAuthBuf.toString(), clientId);
        packAuthBuf.writeBytes(Arrays.copyOfRange(result, 0, 10));
        return packAuthBuf;
    }

    private ByteBuf serverNameIndicate(String serverUrl) {
        ByteBuf sniBuf = Unpooled.buffer();
        byte[] url = serverUrl.getBytes();
        sniBuf.writeByte(0x00);
        sniBuf.writeByte(url.length);
        sniBuf.writeBytes(url);
        sniBuf.writeBytes(new byte[]{0x00, 0x00});
        sniBuf.writeByte(url.length + 2);
        sniBuf.writeByte(url.length );
        byte[] data = new byte[sniBuf.readableBytes()];
        sniBuf.getBytes(0, data);
        sniBuf.writeBytes(data);
        return sniBuf;
    }



    private ByteBuf clientEncode(ByteBuf buf) throws NoSuchAlgorithmException, InvalidKeyException {
        if (hasSentHeader) {
            buf.retain();
            return buf;
        }
        if (handshakeStatus == 8) {
            ByteBuf result = Unpooled.buffer();
            while (buf.readableBytes() > 2048) {
                byte[] randomBytes = new byte[2];
                SecureRandom.getInstanceStrong().nextBytes(randomBytes);
                ByteBuf tmp = Unpooled.buffer(2);
                tmp.writeBytes(randomBytes);
                int size = (int) Math.min(tmp.readUnsignedInt() % 4096 + 100, buf.readableBytes());
                result.writeBytes(unhexlify("17"));
                result.writeBytes(TLS_VERSION);
                result.writeInt(size);
                buf.readBytes(result, size);
            }
            if (buf.readableBytes() <= 0) {
                result.writeBytes(unhexlify("17"));
                result.writeBytes(TLS_VERSION);
                result.writeInt(buf.readableBytes());
                buf.readBytes(result, buf.readableBytes());
            }
            return result;
        } else if (handshakeStatus == 0) {
            ByteBuf tlsHeadBuf = Unpooled.buffer();
            tlsHeadBuf.writeBytes(packAuthData(clientId));
            String host = ssConfig.getMockServerName();
            tlsHeadBuf.writeBytes(serverNameIndicate(host));
            tlsHeadBuf.writeBytes(unhexlify("00170000"));

            if (!ticketBufCache.containsKey(host)) {
                byte[] randomBytes = new byte[2];
                SecureRandom.getInstanceStrong().nextBytes(randomBytes);
                ByteBuf ticketBuf = Unpooled.buffer();
                ticketBuf.writeBytes(randomBytes);
                long len = ((ticketBuf.readUnsignedInt() % 17) + 8) * 16;
                byte[] ticketRandomBytes = new byte[(int) len];
                SecureRandom.getInstanceStrong().nextBytes(ticketRandomBytes);
                ticketBufCache.put(host, ticketRandomBytes);
            }
            ByteBuf ext = Unpooled.buffer();
            ext.writeBytes(unhexlify("ff01000100"));
            ext.writeBytes(unhexlify("0023"));
            ext.writeInt(ticketBufCache.get(host).length);
            ext.writeBytes(ticketBufCache.get(host));
            ext.writeBytes(unhexlify("000d001600140601060305010503040104030301030302010203"));
            ext.writeBytes(unhexlify("000500050100000000"));
            ext.writeBytes(unhexlify("00120000"));
            ext.writeBytes(unhexlify("75500000"));
            ext.writeBytes(unhexlify("000b00020100"));
            ext.writeBytes(unhexlify("000a0006000400170018"));

            tlsHeadBuf.writeInt(ext.readableBytes());
            tlsHeadBuf.writeBytes(ext);
            ByteBuf data = Unpooled.buffer();
            data.writeBytes(unhexlify("0100"));
            data.writeInt(tlsHeadBuf.readableBytes());
            data.writeBytes(tlsHeadBuf);
            ByteBuf resultData = Unpooled.buffer();
            resultData.writeBytes(unhexlify("160301"));
            resultData.writeInt(data.readableBytes());
            resultData.writeBytes(data);
            return resultData;
        } else if (handshakeStatus == 1 && buf.readableBytes() == 0) {
            ByteBuf tlsHeadBuf = Unpooled.buffer();
            tlsHeadBuf.writeBytes(unhexlify("14"));
            tlsHeadBuf.writeBytes(TLS_VERSION);
            tlsHeadBuf.writeBytes(unhexlify("000101")); //ChangeCipherSpec
            tlsHeadBuf.writeBytes(unhexlify("16"));
            tlsHeadBuf.writeBytes(TLS_VERSION);
            tlsHeadBuf.writeBytes(unhexlify("0020")); //Finished
            byte[] randomBytes = new byte[22];
            SecureRandom.getInstanceStrong().nextBytes(randomBytes);
            tlsHeadBuf.writeBytes(randomBytes); //Finished
            byte[] result = hmacWithSha1("HmacSHA1", tlsHeadBuf.toString(), clientId);
            tlsHeadBuf.writeBytes(Arrays.copyOfRange(result, 0, 10));
            sendBuffer.clear();
            handshakeStatus = 8;
            return tlsHeadBuf;
        }
        return Unpooled.buffer();
    }

    private ByteBuf clientDecode(ByteBuf buf) {
        // TODO
        return buf;
    }

    private ByteBuf serverEncode(ByteBuf buf) {
        // TODO
        return buf;
    }

    private ByteBuf serverDecode(ByteBuf buf) {
        // TODO
        return buf;
    }

    public static void main(String[] args) {
        ByteBuf desBuf = Unpooled.buffer();
        desBuf.writeBytes("afsfasfsdfsafa".getBytes());
        desBuf.readableBytes();
        desBuf.clear();
    }
}
