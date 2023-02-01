package org.easysocks.ssserver.cipher;

import io.netty.buffer.ByteBuf;
import io.netty.buffer.Unpooled;
import java.io.ByteArrayOutputStream;
import java.nio.ByteBuffer;
import java.security.SecureRandom;
import java.util.Arrays;
import lombok.extern.slf4j.Slf4j;
import org.bouncycastle.crypto.InvalidCipherTextException;
import org.bouncycastle.crypto.digests.SHA1Digest;
import org.bouncycastle.crypto.generators.HKDFBytesGenerator;
import org.bouncycastle.crypto.modes.AEADCipher;
import org.bouncycastle.crypto.modes.ChaCha20Poly1305;
import org.bouncycastle.crypto.params.AEADParameters;
import org.bouncycastle.crypto.params.HKDFParameters;
import org.bouncycastle.crypto.params.KeyParameter;

@Slf4j
public class Chacha20AeadCipher implements AeadCipher {
    private static final int PAYLOAD_SIZE_MASK = 0x3FFF;
    private static final byte[] INFO = "ss-subkey".getBytes();
    private static final int TAG_LENGTH = 16;
    private static final int NONCE_LENGTH = 12;
    private static final byte[] ZERO_NONCE = new byte[NONCE_LENGTH];
    private final AeadCipherEnum aeadCipher;
    private final String masterKey;
    private boolean isForUdp = false;
    private boolean encryptSaltSet;
    private boolean decryptSaltSet;
    private byte[] encodeSubKey;
    private byte[] decodeSubKey;
    private final byte[] encodeNonce = new byte[NONCE_LENGTH];
    private final byte[] decodeNonce = new byte[NONCE_LENGTH];
    private AEADCipher encodeCipher;
    private AEADCipher decodeCipher;
    private final byte[] decodeBuffer = new byte[2 + TAG_LENGTH + PAYLOAD_SIZE_MASK + TAG_LENGTH];
    private int payloadLenRead = 0;
    private int payloadRead = 0;

    public Chacha20AeadCipher(AeadCipherEnum aeadCipher, String password) {
        this.aeadCipher = aeadCipher;
        this.masterKey = password;
    }

    @Override
    public byte[] encrypt(byte[] src) throws Exception {
        ByteBuf desByteBuf = Unpooled.buffer();

        if (!encryptSaltSet || isForUdp) {
            byte[] salt = randomBytes(aeadCipher.getSaltSize());
            desByteBuf.writeBytes(salt);
            System.out.println("encrypt salt: " + Arrays.toString(salt));
            encodeSubKey = genSubKey(salt);
            encodeCipher = new ChaCha20Poly1305();
            encryptSaltSet = true;
        }
        if (!isForUdp) {
            tcpEncrypt(src, desByteBuf);
        }
//        else {
//            udpEncrypt(src, desByteBuf);
//        }
        byte[] result = new byte[desByteBuf.writerIndex()];
        desByteBuf.readBytes(result);
        return result;
    }
    @Override
    public byte[] decrypt(byte[] src) throws Exception {
        ByteBuf desByteBuf = Unpooled.buffer();
        ByteBuf srcBuf = Unpooled.buffer();
        srcBuf.writeBytes(src);
        byte[] remaining;
        if (!decryptSaltSet || isForUdp) {
            byte[] salt = new byte[aeadCipher.getSaltSize()];
            srcBuf.readBytes(salt, 0, salt.length);
            System.out.println("decrypt salt: " + Arrays.toString(salt));
            decodeSubKey = genSubKey(salt);
            decodeCipher = new ChaCha20Poly1305();
            decryptSaltSet = true;
            remaining = new byte[srcBuf.readableBytes()];
            srcBuf.readBytes(remaining);
        } else {
            remaining = src;
        }
        if (!isForUdp) {
            tcpDecrypt(remaining, desByteBuf);
        }
        byte[] result = new byte[desByteBuf.writerIndex()];
        desByteBuf.readBytes(result);
        return result;
    }

    /** AE_encrypt(key, nonce, message) => (ciphertext, tag)
     * TCP:[encrypted payload length][length tag][encrypted payload][payload tag]
     */
    private void tcpEncrypt(byte[] src, ByteBuf desByteBuf)
        throws InvalidCipherTextException {
        ByteBuf srcBuf = Unpooled.copiedBuffer(src);
        while (srcBuf.isReadable()) {
            // start write encrypted payload length and length tag
            int payloadLength = Math.min(srcBuf.readableBytes(), PAYLOAD_SIZE_MASK);
            byte[] payloadLengthInput = Unpooled.buffer(2).writeShort(payloadLength).array();

            encodeCipher.init(true, new AEADParameters(
                new KeyParameter(encodeSubKey),
                TAG_LENGTH * 8,
                Arrays.copyOf(encodeNonce, NONCE_LENGTH)
            ));
            byte[] encryptedPayloadLengthAndTagOutput = new byte[encodeCipher.getOutputSize(2)];
            // pos output bytes include ciphertext and tag.
            int lenPos = encodeCipher.processBytes(payloadLengthInput, 0, 2, encryptedPayloadLengthAndTagOutput, 0);
            lenPos += encodeCipher.doFinal(
                encryptedPayloadLengthAndTagOutput,
                lenPos
            );
            desByteBuf.writeBytes(encryptedPayloadLengthAndTagOutput, 0, lenPos);
            increment(this.encodeNonce);

            // start write encrypted payload and payload tag
            byte[] payloadInput = new byte[payloadLength];
            srcBuf.readBytes(payloadInput);

            encodeCipher.init(true,  new AEADParameters(
                new KeyParameter(encodeSubKey),
                TAG_LENGTH * 8,
                Arrays.copyOf(encodeNonce, NONCE_LENGTH)
            ));
            byte[] payloadOutput = new byte[encodeCipher.getOutputSize(payloadLength)];

            int payloadPos = encodeCipher.processBytes(payloadInput, 0, payloadLength, payloadOutput, 0);
            payloadPos += encodeCipher.doFinal(payloadOutput, payloadPos);
            desByteBuf.writeBytes(payloadOutput, 0, payloadPos);
            increment(this.encodeNonce);
        }
    }

    /** AE_decrypt(key, nonce, ciphertext, tag) => message
     * TCP:[encrypted payload length][length tag][encrypted payload][payload tag]
     */
    private void tcpDecrypt(byte[] src, ByteBuf desByteBuf) throws InvalidCipherTextException {
        ByteBuf srcBuf = Unpooled.buffer();
        srcBuf.writeBytes(src);
        while (srcBuf.isReadable()) {
            log.info("tcpDecrypt: src readable: {} payloadLenRead:{} payloadRead:{}", srcBuf.isReadable(), payloadLenRead, payloadRead);
            // [encrypted payload length][length tag]
            if (payloadRead == 0) {
                int lengthChunk = 2 + TAG_LENGTH - payloadLenRead;
                int remaining = srcBuf.readableBytes();
                if (remaining < lengthChunk) {
                    srcBuf.readBytes(decodeBuffer, payloadLenRead, remaining);
                    payloadLenRead += remaining;
                    return;
                } else {
                    srcBuf.readBytes(decodeBuffer, payloadLenRead, lengthChunk);
                }

                decodeCipher.init(false, new AEADParameters(
                    new KeyParameter(decodeSubKey),
                    TAG_LENGTH * 8,
                    Arrays.copyOf(decodeNonce, NONCE_LENGTH)
                ));

                decodeCipher.doFinal(
                    decodeBuffer,
                    decodeCipher.processBytes(decodeBuffer, 0, 2 + TAG_LENGTH,
                        decodeBuffer, 0)
                );
                increment(decodeNonce);
            }

            // [encrypted payload][payload tag]
            int payloadLength = Unpooled.wrappedBuffer(decodeBuffer).readUnsignedShort();
            if (payloadLength == 0) {
                return;
            }
            log.info("tcpDecrypt: src readable: {}, payloadRead:{}", srcBuf.isReadable(), payloadRead);
            int payloadChunk = payloadLength + TAG_LENGTH - payloadRead;
            int remaining = srcBuf.readableBytes();
            if (remaining < payloadChunk) {
                srcBuf.readBytes(decodeBuffer, 2 + TAG_LENGTH + payloadRead, remaining);
                payloadRead += remaining;
                return;
            } else {
                srcBuf.readBytes(decodeBuffer, 2 + TAG_LENGTH + payloadRead, payloadChunk);
            }

            decodeCipher.init(false, new AEADParameters(
                new KeyParameter(decodeSubKey),
                TAG_LENGTH * 8,
                Arrays.copyOf(decodeNonce, NONCE_LENGTH)
            ));

            decodeCipher.doFinal(
                decodeBuffer,
                2 + TAG_LENGTH + decodeCipher.processBytes(
                    decodeBuffer, 2 + TAG_LENGTH, payloadLength + TAG_LENGTH,
                    decodeBuffer, 2 + TAG_LENGTH)
            );
            desByteBuf.writeBytes(decodeBuffer, 2 + TAG_LENGTH, payloadLength);
            increment(decodeNonce);

            payloadLenRead = 0;
            payloadRead = 0;
        }
    }

    /**
     * UDP:[salt][encrypted payload][tag]
     */
    private void udpEncrypt(byte[] data, ByteArrayOutputStream stream) throws Exception {
        ByteBuffer buffer = ByteBuffer.wrap(data);
        int remaining = buffer.remaining();
        buffer.get(decodeBuffer, 0, remaining);
        encodeCipher.init(true, new AEADParameters(
            new KeyParameter(encodeSubKey),
            TAG_LENGTH * 8,
            ZERO_NONCE
        ));
        encodeCipher.doFinal(
            decodeBuffer,
            encodeCipher.processBytes(decodeBuffer, 0, remaining, decodeBuffer, 0)
        );
        stream.write(decodeBuffer, 0, remaining + TAG_LENGTH);
    }

    private void udpDecrypt(byte[] data, ByteArrayOutputStream stream) throws Exception {
        ByteBuffer buffer = ByteBuffer.wrap(data);
        int remaining = buffer.remaining();
        buffer.get(decodeBuffer, 0, remaining);
        decodeCipher.init(false, new AEADParameters(
            new KeyParameter(decodeSubKey),
            TAG_LENGTH * 8,
            ZERO_NONCE
        ));
        decodeCipher.doFinal(
            decodeBuffer,
            decodeCipher.processBytes(decodeBuffer, 0, remaining, decodeBuffer, 0)
        );
        stream.write(decodeBuffer, 0, remaining - TAG_LENGTH);
    }

    private byte[] randomBytes(int size) {
        byte[] bytes = new byte[size];
        new SecureRandom().nextBytes(bytes);
        return bytes;
    }

    /** HKDF_SHA1 is a function that takes a secret key, a non-secret salt, an info string,
     * and produces a subkey that is cryptographically strong even if the input secret key is weak.
     * HKDF_SHA1(key, salt, info) => subkey
     */
    private byte[] genSubKey(byte[] salt) {
        HKDFBytesGenerator hkdf = new HKDFBytesGenerator(new SHA1Digest());
        hkdf.init(new HKDFParameters(masterKey.getBytes(), salt, INFO));
        byte[] subKeyBytes = new byte[aeadCipher.getKeySize()];
        hkdf.generateBytes(subKeyBytes, 0, subKeyBytes.length);
        return subKeyBytes;
    }

    private void increment(byte[] nonce) {
        for (int i = 0; i < nonce.length; i++) {
            ++nonce[i];
            if (nonce[i] != 0) {
                break;
            }
        }
    }

    public static void main(String[] args) throws Exception {
        Chacha20AeadCipher aes256GcmCipher1 = new Chacha20AeadCipher(
            AeadCipherEnum.AEAD_CHACHA20_POLY1305, "aes-256-gcm");
        byte[] rawBytes = "是发放连接了 *（JFDSD∂åƒåƒ".getBytes();
        byte[] encodeOutput = aes256GcmCipher1.encrypt(rawBytes);
        System.out.println(rawBytes.length);

        Chacha20AeadCipher aes256GcmCipher2 = new Chacha20AeadCipher(
            AeadCipherEnum.AEAD_CHACHA20_POLY1305, "aes-256-gcm");
        byte[] decodeOutput = aes256GcmCipher2.decrypt(encodeOutput);
        System.out.println(decodeOutput.length);
        System.out.println(Arrays.toString(decodeOutput));
    }
}
