package org.easysocks.ssserver.obfs;

import com.google.common.primitives.Bytes;
import io.netty.buffer.ByteBuf;
import io.netty.buffer.Unpooled;
import io.netty.channel.ChannelHandlerContext;
import io.netty.handler.codec.MessageToMessageCodec;
import java.nio.charset.StandardCharsets;
import java.security.InvalidKeyException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.time.LocalDateTime;
import java.time.ZoneOffset;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Random;
import java.util.stream.IntStream;
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

    private final boolean ssClient;
    private byte[] clientId;
    private final byte[] serverKey;
    private final SsConfig ssConfig;
    private final ByteBuf receiveBuffer = Unpooled.buffer(65535);
    private final ByteBuf sendBuffer = Unpooled.buffer(65535);
    private final Map<String, byte[]> ticketBufCache = new HashMap<>();
    private ClientHandshakeState clientHandshakeState;
    private ServerHandshakeState serverHandshakeState;

    enum ClientHandshakeState {
        NOT_STARTED,
        CLIENT_HELLO_SENT,
        SERVER_HELLO_RECEIVED,
        CLIENT_FINISH_SENT;
    }

    enum ServerHandshakeState {
        NOT_STARTED,
        CLIENT_HELLO_RECEIVED,
        SERVER_HELLO_CENT,
        CLIENT_FINISH_RECEIVED;
    }

    public TlsObfs(SsConfig ssConfig, boolean ssClient) {
        this.ssConfig = ssConfig;
        this.ssClient = ssClient;
        this.serverKey = sha256(ssConfig.getServerKey());
        byte[] randomBytes = new byte[32];
        new Random().nextBytes(randomBytes);
        this.clientId = randomBytes;
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

    private static byte[] hmacWithSha1(String algorithm, byte[] data, byte[] key)
        throws NoSuchAlgorithmException, InvalidKeyException {
        SecretKeySpec secretKeySpec = new SecretKeySpec(key, algorithm);
        Mac mac = Mac.getInstance(algorithm);
        mac.init(secretKeySpec);
        return mac.doFinal(data);
    }

    private static byte[] sha256(String input) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            return digest.digest(
                input.getBytes(StandardCharsets.UTF_8));
        } catch (NoSuchAlgorithmException ignored) {}
        return new byte[32];
    }

    private byte[] generateRandomBytes()
        throws NoSuchAlgorithmException, InvalidKeyException {
        ByteBuf packAuthBuf = Unpooled.buffer();
        byte[] randomBytes = new byte[28];
        SecureRandom.getInstanceStrong().nextBytes(randomBytes);
        packAuthBuf.writeBytes(randomBytes);
        // use first 18 bytes to generate last 10 hmac bytes
        byte[] key = Bytes.concat(
            String.valueOf(LocalDateTime.now().toEpochSecond(ZoneOffset.UTC) / 12*60*60).getBytes(
            StandardCharsets.UTF_8),
            serverKey,
            clientId
        );
        byte[] result = hmacWithSha1("HmacSHA1",Arrays.copyOf(randomBytes, 18), key);
        System.arraycopy(result, 0, randomBytes, 18, 10);
        return result;
    }

    private boolean checkRandomBytes(byte[] randomBytes)
        throws NoSuchAlgorithmException, InvalidKeyException {
        byte[] key = Bytes.concat(
            String.valueOf(LocalDateTime.now().toEpochSecond(ZoneOffset.UTC) / 12*60*60).getBytes(
                StandardCharsets.UTF_8),
            serverKey,
            clientId
        );
        byte[] result = hmacWithSha1("HmacSHA1",Arrays.copyOf(randomBytes, 18), key);
        for (int i = 0; i < 10; i++) {
            if (result[i] != randomBytes[i+18]) {
                return false;
            }
        }
        return true;
    }

    private byte[] generateSessionTicket() {
        byte[] ticket = new byte[192];
        byte[] key = Bytes.concat(
            String.valueOf(LocalDateTime.now().toEpochSecond(ZoneOffset.UTC) / 3600).getBytes(
                StandardCharsets.UTF_8),
            serverKey,
            clientId
        );
        long seed = IntStream.range(0, key.length).map(idx -> key[idx]).sum();
        new Random(seed).nextBytes(ticket);
        return ticket;
    }

    private byte[] generateEncryptedData(int resultLen, byte[] data)
        throws NoSuchAlgorithmException, InvalidKeyException {
        ByteBuf packAuthBuf = Unpooled.buffer();
        byte[] randomBytes = new byte[resultLen];
        SecureRandom.getInstanceStrong().nextBytes(randomBytes);
        packAuthBuf.writeBytes(randomBytes);
        byte[] result = hmacWithSha1("HmacSHA1", data, Bytes.concat(serverKey, clientId));
        System.arraycopy(result, 0, randomBytes, resultLen-10, 10);
        return result;
    }

    private void serverNameIndicate(TlsExtServerName tlsExtServerName) {
        byte[] host = ssConfig.getObfsHost().getBytes();
        tlsExtServerName.setExtLen(host.length + 3 + 2);
        tlsExtServerName.setServerNameListLen(host.length + 3);
        tlsExtServerName.setServerNameLen(host.length);
    }

    private ByteBuf clientEncode(ByteBuf buf) throws NoSuchAlgorithmException, InvalidKeyException {
        if (clientHandshakeState == ClientHandshakeState.CLIENT_FINISH_SENT) {
            // client application data
            return obfsApplicationData(buf);
        }

        if (buf.readableBytes() > 0) {
            sendBuffer.writeBytes(obfsApplicationData(buf));
        }

        if (clientHandshakeState == ClientHandshakeState.NOT_STARTED) {
            // client hello
            TlsClientHello tlsClientHello = new TlsClientHello();
            tlsClientHello.setRandomUnixTime(LocalDateTime.now().toEpochSecond(ZoneOffset.UTC));
            tlsClientHello.setRandomBytes(generateRandomBytes());
            tlsClientHello.setSessionIdLen((short)32);
            tlsClientHello.setSessionId(clientId);
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
            tlsClientHello.setCompMethods(new byte[]{ 0 });

            // ext begin coding
            // session ticket
            TlsExtSessionTicket tlsExtSessionTicket = new TlsExtSessionTicket();
            String host = ssConfig.getObfsHost();
            if (!ticketBufCache.containsKey(host)) {
                ticketBufCache.put(host, generateSessionTicket());
            }
            tlsExtSessionTicket.setSessionTicketExtLen(ticketBufCache.get(host).length);
            ByteBuf tlsExtSessionTicketByteBuf = TlsExtSessionTicket.encode(tlsExtSessionTicket);
            tlsExtSessionTicketByteBuf.writeBytes(ticketBufCache.get(host));

            // Extension - Server Name Indicate
            TlsExtServerName tlsExtServerName = new TlsExtServerName();
            serverNameIndicate(tlsExtServerName);
            ByteBuf tlsExtServerNameByteBuf = TlsExtServerName.encode(tlsExtServerName);
            tlsExtServerNameByteBuf.writeBytes(ssConfig.getObfsHost().getBytes());

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
            clientHandshakeState = ClientHandshakeState.CLIENT_HELLO_SENT;
            return data;
        } else if (clientHandshakeState == ClientHandshakeState.CLIENT_HELLO_SENT) {
            ByteBuf data = Unpooled.buffer();
            TlsChangeCipherSpec tlsChangeCipherSpec = new TlsChangeCipherSpec();
            data.writeBytes(TlsChangeCipherSpec.encode(tlsChangeCipherSpec));

            TlsEncryptedHandshake tlsEncryptedHandshake = new TlsEncryptedHandshake();
            byte[] randomBytes = generateRandomBytes();
            tlsEncryptedHandshake.setLen(randomBytes.length);
            data.writeBytes(TlsEncryptedHandshake.encode(tlsEncryptedHandshake));
            data.writeBytes(randomBytes);

            data.writeBytes(sendBuffer);
            clientHandshakeState = ClientHandshakeState.CLIENT_FINISH_SENT;
            return data;
        }
        return Unpooled.buffer(0);
    }

    private ByteBuf clientDecode(ByteBuf buf) {
        receiveBuffer.writeBytes(buf);
        if (clientHandshakeState == ClientHandshakeState.CLIENT_FINISH_SENT) {
            // client application data
            return obfsApplicationData(receiveBuffer);
        }
        return buf;
    }

    private ByteBuf serverEncode(ByteBuf buf) throws NoSuchAlgorithmException, InvalidKeyException {
        if (serverHandshakeState == ServerHandshakeState.CLIENT_FINISH_RECEIVED) {
            // server application data
            return obfsApplicationData(buf);
        }

        if (buf.readableBytes() > 0) {
            sendBuffer.writeBytes(obfsApplicationData(buf));
        }

        if (serverHandshakeState == ServerHandshakeState.CLIENT_HELLO_RECEIVED) {
            // server hello
            TlsServerHello tlsServerHello = new TlsServerHello();
            tlsServerHello.setRandomUnixTime(LocalDateTime.now().toEpochSecond(ZoneOffset.UTC));
            tlsServerHello.setRandomBytes(generateRandomBytes());
            tlsServerHello.setSessionIdLen((short) 32);
            tlsServerHello.setSessionId(clientId);

            // change cipher spec
            TlsChangeCipherSpec tlsChangeCipherSpec = new TlsChangeCipherSpec();

            // encrypted handshake
            TlsEncryptedHandshake tlsEncryptedHandshake = new TlsEncryptedHandshake();

            ByteBuf data = Unpooled.buffer();
            data.writeBytes(TlsServerHello.encode(tlsServerHello));
            data.writeBytes(TlsChangeCipherSpec.encode(tlsChangeCipherSpec));
            data.writeBytes(TlsEncryptedHandshake.encode(tlsEncryptedHandshake));

            byte[] dataForEncrypt = new byte[data.readableBytes()];
            data.copy().readBytes(dataForEncrypt);
            byte[] key = Bytes.concat(serverKey, clientId);
            byte[] result = hmacWithSha1("HmacSHA1", dataForEncrypt, key);
            data.writeBytes(result, 0, tlsEncryptedHandshake.getLen());

            serverHandshakeState = ServerHandshakeState.SERVER_HELLO_CENT;
            return data;
        }
        return Unpooled.buffer(0);
    }

    private ByteBuf serverDecode(ByteBuf buf) throws NoSuchAlgorithmException, InvalidKeyException {
        if (serverHandshakeState == ServerHandshakeState.CLIENT_FINISH_RECEIVED) {
            receiveBuffer.writeBytes(buf);
            // server application data
            return deobfsApplicationData(receiveBuffer);
        }
        if (serverHandshakeState == ServerHandshakeState.NOT_STARTED) {
            receiveBuffer.writeBytes(buf);
            if (receiveBuffer.readableBytes() <= TlsClientHello.byteLength) {
                return Unpooled.buffer(0);
            }
            TlsClientHello tlsClientHello = TlsClientHello.decode(receiveBuffer);
            if (tlsClientHello.getContentType() != 0x16) {
                log.error("Error decode tlsClientHello header obfs.");
                return decodeErrorReturn();
            }
            clientId = tlsClientHello.getSessionId();

            byte[] randomBytes = tlsClientHello.getRandomBytes();
            if (!checkRandomBytes(randomBytes)) {
                log.error("Client randomBytes checks failed.");
                // todo
                return decodeErrorReturn();
            }

            // session ticket
            if (receiveBuffer.readableBytes() <=  TlsExtSessionTicket.byteLength) {
                receiveBuffer.resetReaderIndex();
                return Unpooled.buffer(0);
            }
            TlsExtSessionTicket tlsExtSessionTicket = TlsExtSessionTicket.decode(receiveBuffer);
            if (tlsExtSessionTicket.getSessionTicketType() != 0x0023) {
                log.error("Error decode tlsExtSessionTicket header obfs.");
                return decodeErrorReturn();
            }
            int ticketLen = tlsExtSessionTicket.getSessionTicketExtLen();
            if (receiveBuffer.readableBytes() < ticketLen) {
                receiveBuffer.resetReaderIndex();
                return Unpooled.buffer(0);
            }
            receiveBuffer.readBytes(ticketLen);

            // server name indicate
            if (receiveBuffer.readableBytes() <=  TlsExtServerName.byteLength) {
                receiveBuffer.resetReaderIndex();
                return Unpooled.buffer(0);
            }
            TlsExtServerName tlsExtServerName = TlsExtServerName.decode(receiveBuffer);
            int serverNameLen = tlsExtServerName.getServerNameLen();
            if (receiveBuffer.readableBytes() < serverNameLen) {
                receiveBuffer.resetReaderIndex();
                return Unpooled.buffer(0);
            }
            receiveBuffer.readBytes(serverNameLen);

            // tls other ext
            if (receiveBuffer.readableBytes() < TlsExtOthers.byteLength) {
                receiveBuffer.resetReaderIndex();
                return Unpooled.buffer(0);
            }
            receiveBuffer.readBytes(TlsExtOthers.byteLength);
            serverHandshakeState = ServerHandshakeState.SERVER_HELLO_CENT;
        }
        if (serverHandshakeState == ServerHandshakeState.CLIENT_HELLO_RECEIVED) {
            receiveBuffer.writeBytes(buf);
            if (receiveBuffer.readableBytes() < TlsChangeCipherSpec.byteLength) {
                receiveBuffer.resetReaderIndex();
                return Unpooled.buffer(0);
            }
            TlsChangeCipherSpec tlsChangeCipherSpec = TlsChangeCipherSpec.decode(receiveBuffer);
            if (tlsChangeCipherSpec.getContentType() != 0x14) {
                log.error("Error decode tlsChangeCipherSpec header obfs.");
                return decodeErrorReturn();
            }

            if (receiveBuffer.readableBytes() < TlsEncryptedHandshake.byteLength) {
                receiveBuffer.resetReaderIndex();
                return Unpooled.buffer(0);
            }
            TlsEncryptedHandshake tlsEncryptedHandshake = TlsEncryptedHandshake.decode(
                receiveBuffer);
            int encryptedDataLen = tlsEncryptedHandshake.getLen();
            if (receiveBuffer.readableBytes() < encryptedDataLen) {
                receiveBuffer.resetReaderIndex();
                return Unpooled.buffer(0);
            }
            receiveBuffer.readBytes(encryptedDataLen);
            serverHandshakeState = ServerHandshakeState.CLIENT_FINISH_RECEIVED;
        }
        return Unpooled.buffer(0);
    }

    ByteBuf decodeErrorReturn() {
        serverHandshakeState = ServerHandshakeState.NOT_STARTED;
        clientHandshakeState = ClientHandshakeState.NOT_STARTED;
        receiveBuffer.clear();
        sendBuffer.clear();
        ByteBuf result = Unpooled.buffer(2048);
        byte[] r = new byte[2048];
        Arrays.fill(r, (byte)'E');
        result.writeBytes(r);
        return result;
    }

    ByteBuf obfsApplicationData(ByteBuf buf) {
        // client application data
        // 17 - type is 0x17 (application data)
        // 03 03 - protocol version is "3,3" (TLS 1.2)
        // 00 30 - 0x30 (48) bytes of application data follows
        ByteBuf result = Unpooled.buffer();
        while (buf.readableBytes() > 2048) {
            int size = Math.min(
                new Random().nextInt(65536) % 4096 + 100,
                buf.readableBytes()
            );
            result.writeBytes(TLS_DATA_HEADER);
            result.writeShort(size);
            result.writeBytes(buf, size);
        }
        if (buf.readableBytes() > 0) {
            // client application data header
            result.writeBytes(TLS_DATA_HEADER);
            result.writeShort(buf.readableBytes());
            result.writeBytes(buf, buf.readableBytes());
        }
        return result;
    }

    ByteBuf deobfsApplicationData(ByteBuf buf) {
        ByteBuf resultData = Unpooled.buffer(0);
        while (buf.readableBytes() > 5) {
            if (buf.getByte(buf.readerIndex()) != 0x17
                || buf.getByte(buf.readerIndex()+1) != 0x03
                || buf.getByte(buf.readerIndex()+2) != 0x03) {
                log.error("Decode tls application data failed, error header");
                return decodeErrorReturn();
            }
            int size = buf.getUnsignedShort(buf.readerIndex()+3);
            if (buf.readableBytes() < size) {
                break;
            }
            buf.readBytes(5);
            buf.readBytes(resultData, size);
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
