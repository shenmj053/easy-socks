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
import org.easysocks.ssserver.obfs.entity.TlsChangeCipherSpec;
import org.easysocks.ssserver.obfs.entity.TlsClientHello;
import org.easysocks.ssserver.obfs.entity.TlsEncryptedHandshake;
import org.easysocks.ssserver.obfs.entity.TlsExtOthers;
import org.easysocks.ssserver.obfs.entity.TlsExtServerName;
import org.easysocks.ssserver.obfs.entity.TlsExtSessionTicket;
import org.easysocks.ssserver.obfs.entity.TlsServerHello;


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
    private static byte[] TLS_DATA_HEADER = {0x07, 0x03, 0x03};
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


    private short[] randomBytes()
        throws NoSuchAlgorithmException, InvalidKeyException {
        ByteBuf packAuthBuf = Unpooled.buffer();
        byte[] randomBytes = new byte[28];
        SecureRandom.getInstanceStrong().nextBytes(randomBytes);
        packAuthBuf.writeBytes(randomBytes);
        byte[] result = hmacWithSha1("HmacSHA1",Arrays.copyOf(randomBytes, 18), serverKey + clientId);
        System.arraycopy(result, 0, randomBytes, 18, 10);
        short[] randomBytesShort = new short[28];
        for (int i = 0; i < randomBytes.length; i++) {
            randomBytesShort[i] = randomBytes[i];
        }
        return randomBytesShort;
    }

    private short[] generateEncryptedData(int len, byte[] data)
        throws NoSuchAlgorithmException, InvalidKeyException {
        ByteBuf packAuthBuf = Unpooled.buffer();
        byte[] randomBytes = new byte[len];
        SecureRandom.getInstanceStrong().nextBytes(randomBytes);
        packAuthBuf.writeBytes(randomBytes);
        byte[] result = hmacWithSha1("HmacSHA1", data, serverKey + clientId);
        System.arraycopy(result, 0, randomBytes, len-10, 10);
        short[] randomBytesShort = new short[len];
        for (int i = 0; i < randomBytes.length; i++) {
            randomBytesShort[i] = randomBytes[i];
        }
        return randomBytesShort;
    }

    private void serverNameIndicate(TlsExtServerName tlsExtServerName) {
        byte[] host = ssConfig.getMockServerName().getBytes();
        tlsExtServerName.setExtLen(host.length + 3 + 2);
        tlsExtServerName.setServerNameListLen(host.length + 3);
        tlsExtServerName.setServerNameLen(host.length);
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
        if (handshakeStatus == 1) {
            // client application data
            return obfsApplicationData(buf);
        }

        if (handshakeStatus == 0) {
            // client hello
            TlsClientHello tlsClientHello = new TlsClientHello();
            tlsClientHello.setRandomUnixTime(LocalDateTime.now().toEpochSecond(ZoneOffset.UTC));
            tlsClientHello.setRandomBytes(randomBytes());
            tlsClientHello.setSessionIdLen((short)32);
            short[] sessionId = new short[32];
            for (int i = 0; i < clientId.getBytes().length; i++) {
                sessionId[i] = clientId.getBytes()[i];
            }
            tlsClientHello.setSessionId(sessionId);
            tlsClientHello.setCipherSuitesLen(56);
            tlsClientHello.setCipherSuites(
                new short[]{
                    0xc0, 0x2c, 0xc0, 0x30, 0x00, 0x9f, 0xcc, 0xa9, 0xcc, 0xa8, 0xcc, 0xaa, 0xc0, 0x2b, 0xc0, 0x2f,
                    0x00, 0x9e, 0xc0, 0x24, 0xc0, 0x28, 0x00, 0x6b, 0xc0, 0x23, 0xc0, 0x27, 0x00, 0x67, 0xc0, 0x0a,
                    0xc0, 0x14, 0x00, 0x39, 0xc0, 0x09, 0xc0, 0x13, 0x00, 0x33, 0x00, 0x9d, 0x00, 0x9c, 0x00, 0x3d,
                    0x00, 0x3c, 0x00, 0x35, 0x00, 0x2f, 0x00, 0xff
                }
            );
            tlsClientHello.setCompMethodsLen((short)1);
            tlsClientHello.setCompMethods(new short[]{ 0 });

            // ext begin coding
            // session ticket
            TlsExtSessionTicket tlsExtSessionTicket = new TlsExtSessionTicket();
            String host = ssConfig.getMockServerName();
            if (!ticketBufCache.containsKey(host)) {
                int len = ((SecureRandom.getInstanceStrong().nextInt(65536) % 17) + 8) * 16;
                byte[] ticketRandomBytes = new byte[len];
                SecureRandom.getInstanceStrong().nextBytes(ticketRandomBytes);
                ticketBufCache.put(host, ticketRandomBytes);
            }
            tlsExtSessionTicket.setSessionTicketExtLen(ticketBufCache.get(host).length);
            ByteBuf tlsExtSessionTicketByteBuf = TlsExtSessionTicket.encode(tlsExtSessionTicket);
            tlsExtSessionTicketByteBuf.writeBytes(ticketBufCache.get(host));

            // Extension - Server Name Indicate
            TlsExtServerName tlsExtServerName = new TlsExtServerName();
            serverNameIndicate(tlsExtServerName);
            ByteBuf tlsExtServerNameByteBuf = TlsExtServerName.encode(tlsExtServerName);
            tlsExtServerNameByteBuf.writeBytes(ssConfig.getMockServerName().getBytes());

            /* Other Extensions */
            TlsExtOthers tlsExtOthers = new TlsExtOthers();
            ByteBuf tlsExtOthersByteBuf = TlsExtOthers.encode(tlsExtOthers);

            // update len field
            ByteBuf tlsClientHelloByteBuf = TlsClientHello.encode(tlsClientHello);
            tlsClientHello.setLen(tlsClientHelloByteBuf.readableBytes() - 5);
            tlsClientHello.setHandshakeLen2(tlsClientHelloByteBuf.readableBytes() - 9);
            tlsClientHello.setExtLen(
                tlsExtSessionTicketByteBuf.readableBytes()
                + tlsExtServerNameByteBuf.readableBytes()
                + tlsExtOthersByteBuf.readableBytes()
            );

            ByteBuf data = Unpooled.buffer();
            data.writeBytes(TlsClientHello.encode(tlsClientHello));
            data.writeBytes(tlsExtSessionTicketByteBuf);
            data.writeBytes(tlsExtServerNameByteBuf);
            data.writeBytes(tlsExtOthersByteBuf);
            handshakeStatus = 1;
            return data;
        }
        return Unpooled.buffer();
    }

    private ByteBuf clientDecode(ByteBuf buf) {
        // TODO
        return buf;
    }

    private ByteBuf serverEncode(ByteBuf buf) throws NoSuchAlgorithmException, InvalidKeyException {
        if (hasSentHeader) {
            buf.retain();
            return buf;
        }
        if (handshakeStatus == -1) {
            buf.retain();
            return buf;
        }
        if (handshakeStatus == 1) {
            // server application data
            return obfsApplicationData(buf);
        } else if (handshakeStatus == 0) {
            // server hello
            TlsServerHello tlsServerHello = new TlsServerHello();
            tlsServerHello.setRandomUnixTime(LocalDateTime.now().toEpochSecond(ZoneOffset.UTC));
            tlsServerHello.setRandomBytes(randomBytes());
            tlsServerHello.setSessionIdLen((short)32);
            short[] sessionId = new short[32];
            for (int i = 0; i < clientId.getBytes().length; i++) {
                sessionId[i] = clientId.getBytes()[i];
            }
            tlsServerHello.setSessionId(sessionId);

            // change cipher spec
            TlsChangeCipherSpec tlsChangeCipherSpec = new TlsChangeCipherSpec();

            // encrypted handshake
            TlsEncryptedHandshake tlsEncryptedHandshake = new TlsEncryptedHandshake();
            tlsEncryptedHandshake.setLen(64);

            ByteBuf data = Unpooled.buffer();
            data.writeBytes(TlsServerHello.encode(tlsServerHello));
            data.writeBytes(TlsChangeCipherSpec.encode(tlsChangeCipherSpec));
            data.writeBytes(TlsEncryptedHandshake.encode(tlsEncryptedHandshake));
            byte[] dataForEncrypt = new byte[data.readableBytes()];
            data.copy().readBytes(dataForEncrypt);
            short[] encryptedData = generateEncryptedData(64, dataForEncrypt);
            for (short b: encryptedData) {
                data.writeByte(b);
            }
            return data;
        }
        return Unpooled.buffer();
    }

    private ByteBuf serverDecode(ByteBuf buf) throws NoSuchAlgorithmException, InvalidKeyException {
        if (handshakeStatus == -1) {
            buf.retain();
            return buf;
        }
        if (handshakeStatus == 1) {
            return deobfsApplicationData(buf);
        } else if (handshakeStatus == 0) {
            receiveBuffer.resetReaderIndex();
            receiveBuffer.writeBytes(buf);
            int readableBytes = receiveBuffer.readableBytes();
            readableBytes -= TlsClientHello.byteLength;
            if (readableBytes <= 0) {
                return Unpooled.buffer();
            }
            TlsClientHello tlsClientHello = TlsClientHello.decode(receiveBuffer);
            if (tlsClientHello.getContentType() != 0x16) {
                log.error("Error decode tlsClientHello header obfs.");
                return Unpooled.buffer();
            }
            readableBytes -= TlsExtSessionTicket.byteLength;
            if (readableBytes <= 0) {
                return Unpooled.buffer();
            }
            TlsExtSessionTicket tlsExtSessionTicket = TlsExtSessionTicket.decode(receiveBuffer);
            if (tlsExtSessionTicket.getSessionTicketType() != 0x0023) {
                log.error("Error decode tlsExtSessionTicket header obfs.");
                return Unpooled.buffer();
            }
            int ticketLen = tlsExtSessionTicket.getSessionTicketExtLen();
            if (readableBytes < ticketLen) {
                return Unpooled.buffer();
            }
            clireceiveBuffer.readBytes(ticketLen);





        }
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

    ByteBuf obfsApplicationData(ByteBuf buf) throws NoSuchAlgorithmException {
        // client application data
        // 17 - type is 0x17 (application data)
        // 03 03 - protocol version is "3,3" (TLS 1.2)
        // 00 30 - 0x30 (48) bytes of application data follows
        ByteBuf result = Unpooled.buffer();
        while (buf.readableBytes() > 2048) {
            int size = Math.min(
                SecureRandom.getInstanceStrong().nextInt(65536) % 4096 + 100,
                buf.readableBytes()
            );
            result.writeBytes(TLS_DATA_HEADER);
            result.writeInt(size);
            result.writeBytes(buf, size);
        }
        if (buf.readableBytes() <= 0) {
            // client application data header
            result.writeBytes(TLS_DATA_HEADER);
            result.writeShort(buf.readableBytes());
            result.writeBytes(buf, buf.readableBytes());
        }
        return result;
    }

    ByteBuf deobfsApplicationData(ByteBuf buf) {
        ByteBuf resultData = Unpooled.buffer();
        while (buf.readableBytes() > 5) {
            if (buf.readByte() != 0x17 || buf.readByte() != 0x03
                || buf.readByte() != 0x03) {
                log.error("server decode appdata error");
                return Unpooled.buffer(0);
            }
            int size = buf.readUnsignedShort();
            if (buf.readableBytes() < size) {
                break;
            }
            resultData.writeBytes(buf, size);
        }
        return resultData;

    }

    public static void main(String[] args) {
        TlsClientHello tlsClientHello = new TlsClientHello();
        System.out.println(tlsClientHello);

        ByteBuf b = TlsClientHello.encode(tlsClientHello);
        TlsClientHello tlsClientHello2= TlsClientHello.decode(b);

        System.out.println(tlsClientHello2);
    }
}
