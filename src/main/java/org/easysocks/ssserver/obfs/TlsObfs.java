package org.easysocks.ssserver.obfs;

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
import lombok.extern.slf4j.Slf4j;
import org.easysocks.ssserver.config.SsConfig;

/**
 * tls header encode and decode, reference site below:
 * <a href="https://tls12.xargs.org/">...</a>
 */
@Slf4j
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
    private static byte[] SERVER_CHANGE_CIPHER_SPEC = {0x14, 0x03, 0x03, 0x00, 0x01, 0x01};
    private static byte[] SERVER_HANDSHAKE_FINISH = {0x16, 0x03, 0x03};



    private final boolean ssClient;
    private final String clientId;
    private final String serverKey;
    private final SsConfig ssConfig;

    private int handshakeStatus = 0;
    private int overhead = 5;

    private int serverInfoOverhead;
    private boolean hasSentHeader = false;
    private boolean hasReceivedHeader = false;
    private final ByteBuf receiveBuffer = Unpooled.buffer(65535);
    private final ByteBuf sendBuffer = Unpooled.buffer(65535);

    private Map<String, byte[]> ticketBufCache;

    public TlsObfs(SsConfig ssConfig, boolean ssClient, String serverKey, String clientId) {
        this.ssConfig = ssConfig;
        this.ssClient = ssClient;
        this.serverKey = serverKey;
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
    protected void decode(ChannelHandlerContext ctx, Object msg, List<Object> out)
        throws NoSuchAlgorithmException, InvalidKeyException {
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

    private static byte[] hmacWithSha1(String algorithm, byte[] data, String key)
        throws NoSuchAlgorithmException, InvalidKeyException {
        SecretKeySpec secretKeySpec = new SecretKeySpec(key.getBytes(), algorithm);
        Mac mac = Mac.getInstance(algorithm);
        mac.init(secretKeySpec);
        return mac.doFinal(data);
    }


    static private ByteBuf packAuthData(String clientId)
        throws NoSuchAlgorithmException, InvalidKeyException {
        ByteBuf packAuthBuf = Unpooled.buffer();
        long epochSecond = LocalDateTime.now().toEpochSecond(ZoneOffset.UTC);
        packAuthBuf.writeInt((int)epochSecond);
        byte[] randomBytes = new byte[18];
        SecureRandom.getInstanceStrong().nextBytes(randomBytes);
        packAuthBuf.writeBytes(randomBytes);

        byte[] result = hmacWithSha1("HmacSHA1", packAuthBuf.array(), clientId);
        packAuthBuf.writeBytes(Arrays.copyOfRange(result, 0, 10));
        return packAuthBuf;
    }

    static private ByteBuf serverNameIndicate(String serverUrl) {
        ByteBuf snieBuf = Unpooled.buffer();
        byte[] url = serverUrl.getBytes();
        snieBuf.writeByte(0x00);
        snieBuf.writeShort(url.length);
        snieBuf.writeBytes(url);
        ByteBuf result = Unpooled.buffer();
        result.writeBytes(new byte[]{0x00, 0x00});
        result.writeShort(snieBuf.readableBytes() + 2);
        result.writeShort(snieBuf.readableBytes());
        result.writeBytes(snieBuf);
        return result;
    }

    private ByteBuf clientEncode(ByteBuf buf) throws NoSuchAlgorithmException, InvalidKeyException {
        if (hasSentHeader) {
            buf.retain();
            return buf;
        }
        if (handshakeStatus == -1) {
            buf.retain();
            return buf;
        }
        if (handshakeStatus == 8) {
            // client application data
            // 17 - type is 0x17 (application data)
            // 03 03 - protocol version is "3,3" (TLS 1.2)
            // 00 30 - 0x30 (48) bytes of application data follows
            ByteBuf result = Unpooled.buffer();
            while (buf.readableBytes() > 2048) {
                byte[] randomBytes = new byte[2];
                SecureRandom.getInstanceStrong().nextBytes(randomBytes);
                ByteBuf tmp = Unpooled.buffer(2);
                tmp.writeBytes(randomBytes);
                int size = (int) Math.min(tmp.readUnsignedInt() % 4096 + 100, buf.readableBytes());
                result.writeBytes(APPLICATION_DATA);
                result.writeBytes(TLS_VERSION);
                result.writeInt(size);
                buf.readBytes(result, size);
            }
            if (buf.readableBytes() <= 0) {
                // client application data header
                result.writeBytes(APPLICATION_DATA);
                result.writeBytes(TLS_VERSION);
                result.writeShort(buf.readableBytes());
                buf.readBytes(result, buf.readableBytes());
            }
            return result;
        }

        if (buf.readableBytes() > 0) {
            sendBuffer.writeBytes(APPLICATION_DATA);
            sendBuffer.writeBytes(TLS_VERSION);
            sendBuffer.writeShort(buf.readableBytes());
            sendBuffer.writeBytes(buf);
        }

        if (handshakeStatus == 0) {
            handshakeStatus = 1;
            // client hello
            // 16 - type is 0x16 (handshake record)
            // 03 01 - protocol version is 3.1 (also known as TLS 1.0)
            // 00 a5 - 0xA5 (165) bytes of handshake message follows
            ByteBuf tlsHeadBuf = Unpooled.buffer();
            // Client Version
            tlsHeadBuf.writeBytes(TLS_VERSION);
            // Client Random, 32 bytes
            tlsHeadBuf.writeBytes(packAuthData(serverKey + clientId));
            // Session ID length
            // 32 bytes hardcode
            tlsHeadBuf.writeBytes(unhexlify("20"));
            // Session ID data
            // clientId is 32 bytes
            tlsHeadBuf.writeBytes(unhexlify(clientId));
            // Cipher Suites 32 bytes
            tlsHeadBuf.writeBytes(unhexlify("001cc02bc02fcca9cca8cc14cc13c00ac014c009c013009c0035002f000a"));
            // Compression Methods
            tlsHeadBuf.writeBytes(unhexlify("0100"));

            // ext begin coding
            ByteBuf ext = Unpooled.buffer();
            // Extension - Server Name
            String host = ssConfig.getMockServerName();
            ext.writeBytes(serverNameIndicate(host));

            // extended master secret
            ext.writeBytes(unhexlify("00170000"));

            if (!ticketBufCache.containsKey(host)) {
                ByteBuf ticketBuf = Unpooled.buffer();
                byte[] randomBytes = new byte[2];
                SecureRandom.getInstanceStrong().nextBytes(randomBytes);
                ticketBuf.writeBytes(randomBytes);
                long len = ((ticketBuf.readUnsignedInt() % 17) + 8) * 16;
                byte[] ticketRandomBytes = new byte[(int) len];
                SecureRandom.getInstanceStrong().nextBytes(ticketRandomBytes);
                ticketBufCache.put(host, ticketRandomBytes);
            }

            // renegotiation info
            ext.writeBytes(unhexlify("ff01000100"));
            // session ticket
            ext.writeBytes(unhexlify("0023"));
            ext.writeShort(ticketBufCache.get(host).length);
            ext.writeBytes(ticketBufCache.get(host));
            // other hard code
            ext.writeBytes(unhexlify("000d001600140601060305010503040104030301030302010203"));
            ext.writeBytes(unhexlify("000500050100000000"));
            // signed certificate timestamp
            ext.writeBytes(unhexlify("00120000"));
            ext.writeBytes(unhexlify("75500000"));
            ext.writeBytes(unhexlify("000b00020100"));
            ext.writeBytes(unhexlify("000a0006000400170018"));
            // end ext coding
            // add ext to header
            tlsHeadBuf.writeShort(ext.readableBytes());
            tlsHeadBuf.writeBytes(ext);

            // Handshake Header
            // Each handshake message starts with a type and a length.
            // 01 - handshake message type 0x01 (client hello)
            // 00 00 a1 - 0xA1 (161) bytes of client hello follows
            ByteBuf data = Unpooled.buffer();
            data.writeBytes(new byte[]{0x01});
            data.writeBytes(new byte[]{0x00});
            data.writeShort(tlsHeadBuf.readableBytes());
            data.writeBytes(tlsHeadBuf);

            // Record Header
            // 16 - type is 0x16 (handshake record)
            // 03 01 - protocol version is 3.1 (also known as TLS 1.0)
            // 00 a5 - 0xA5 (165) bytes of handshake message follows
            ByteBuf resultData = Unpooled.buffer();
            resultData.writeBytes(HANDSHAKE);
            resultData.writeBytes(TLS_VERSION);
            resultData.writeShort(data.readableBytes());
            resultData.writeBytes(data);
            return resultData;
        } else if (handshakeStatus == 1 && buf.readableBytes() == 0) {
            ByteBuf tlsHeadBuf = Unpooled.buffer();
            // client change cipher spec 14 03 03 00 01 01
            // 14 - type is 0x14 (ChangeCipherSpec record)
            // 03 03 - protocol version is "3,3" (TLS 1.2)
            // 00 01 - 0x1 (1) bytes of change cipher spec follows
            // 01 - the payload of this message is defined as the byte 0x01
            tlsHeadBuf.writeBytes(CHANGE_CIPHER);
            tlsHeadBuf.writeBytes(TLS_VERSION);
            tlsHeadBuf.writeBytes(unhexlify("000101"));
            // client handshake finished
            tlsHeadBuf.writeBytes(HANDSHAKE);
            tlsHeadBuf.writeBytes(TLS_VERSION);
            // 32 bytes
            tlsHeadBuf.writeBytes( new byte[]{0x00, 0x20});
            byte[] randomBytes = new byte[22];
            SecureRandom.getInstanceStrong().nextBytes(randomBytes);
            tlsHeadBuf.writeBytes(randomBytes);
            byte[] result = hmacWithSha1("HmacSHA1", tlsHeadBuf.array(), serverKey + clientId);
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

    private ByteBuf serverDecode(ByteBuf buf) throws NoSuchAlgorithmException, InvalidKeyException {
        if ((handshakeStatus & 4) == 4) {
            ByteBuf resultData = Unpooled.buffer();
            receiveBuffer.writeBytes(buf);
            while (receiveBuffer.readableBytes() > 5) {
                if (receiveBuffer.readByte() != 0x17 || receiveBuffer.readByte() != 0x03
                    || receiveBuffer.readByte() != 0x03) {
                    log.error("server decode appdata error");
                    return Unpooled.buffer(0);
                }
                int size = receiveBuffer.readUnsignedShort();
                if (receiveBuffer.readableBytes() < size) {
                    break;
                }
                receiveBuffer.readBytes(resultData, size);
            }
            return resultData;
        }

        if ((handshakeStatus & 1) == 1) {
            receiveBuffer.writeBytes(buf);
            buf = receiveBuffer.copy();
            ByteBuf verify = buf.copy();
            if (buf.readableBytes() < 11) {
                log.error("server decode data error");
                return Unpooled.buffer(0);
            }
            // server change cipher spec
            byte[] serverChangeCipherSpec = new byte[6];
            buf.readBytes(serverChangeCipherSpec, 0, 6);
            if (!Arrays.equals(serverChangeCipherSpec, SERVER_CHANGE_CIPHER_SPEC)) {
                log.error("server decode data error");
                return Unpooled.buffer(0);
            }

            // server handshake finished
            byte[] serverHandshakeFinish = new byte[4];
            buf.readBytes(serverHandshakeFinish, 0, 4);
            if (!Arrays.equals(serverHandshakeFinish, SERVER_HANDSHAKE_FINISH)) {
                log.error("server decode data error");
                return Unpooled.buffer(0);
            }
            int verifyLen = buf.readUnsignedShort();
            if (buf.readableBytes() < verifyLen) {
                log.error("server decode data error");
                return Unpooled.buffer(0);
            }
            byte[] verifyData = new byte[verifyLen];
            verify.readBytes(verifyData, 0, verifyLen);
            byte[] result = hmacWithSha1("HmacSHA1", verifyData, serverKey + clientId);
            byte[] hmacVerifyData = new byte[10];
            verify.readBytes(hmacVerifyData, 0, 10);
            if (!Arrays.equals(Arrays.copyOfRange(result, 0, 10), hmacVerifyData)) {
                log.error("server decode data error");
                return Unpooled.buffer(0);
            }
            receiveBuffer.writeBytes(verify);
            handshakeStatus |= 4;
            return serverDecode(Unpooled.buffer(0));
        }

        receiveBuffer.writeBytes(buf);
        buf = receiveBuffer;
        ByteBuf ognBuf = buf.copy();
        if (buf.readableBytes() < 3) {
            return Unpooled.buffer(0);
        }

        return Unpooled.buffer(0);
    }

    ByteBuf decodeErrorReturn(ByteBuf buf) {
        handshakeStatus = -1;
        if (overhead > 0) {
            serverInfoOverhead -= overhead;
        }
        overhead = 0;
        ByteBuf result = Unpooled.buffer(2048);
        byte[] r = new byte[2048];
        Arrays.fill(r, Byte.parseByte("E"));
        result.writeBytes(r);
        return result;
    }

    public static void main(String[] args) {
        ByteBuf b = serverNameIndicate("example.ulfheim.net");
        byte[] r = new byte[b.readableBytes()];
        b.readBytes(r);
        System.out.println(hexlify(r));
    }
}
