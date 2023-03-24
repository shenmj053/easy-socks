package org.easysocks.ssserver.cipher;

import io.netty.buffer.ByteBuf;
import io.netty.buffer.Unpooled;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.Base64;
import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import lombok.extern.slf4j.Slf4j;
import org.bouncycastle.crypto.digests.SHA1Digest;
import org.bouncycastle.crypto.generators.HKDFBytesGenerator;
import org.bouncycastle.crypto.params.HKDFParameters;
import org.easysocks.ssserver.common.ShadowSocksKey;

@Slf4j
public class Aes256GcmCipher implements AeadCipher {
    private static final int PAYLOAD_SIZE_MASK = 0x3FFF;
    private static final byte[] INFO = "ss-subkey".getBytes();
    private static final int TAG_LENGTH = 16;
    private static final int NONCE_LENGTH = 12;
    private static final byte[] ZERO_NONCE = new byte[NONCE_LENGTH];
    private final AeadCipherEnum aeadCipher;
    private final byte[] ssKey;
    private boolean encryptSaltSet;
    private boolean decryptSaltSet;
    private byte[] encodeSubKey;
    private byte[] decodeSubKey;
    private final byte[] encodeNonce = new byte[NONCE_LENGTH];
    private final byte[] decodeNonce = new byte[NONCE_LENGTH];
    private Cipher encipher;
    private Cipher decipher;
    private final ByteBuf decodeBuffer = Unpooled.buffer();
    private int payloadLength = 0;

    public Aes256GcmCipher(AeadCipherEnum aeadCipher, String password) {
        this.aeadCipher = aeadCipher;
        this.ssKey = new ShadowSocksKey(password).getEncoded();
    }

    @Override
    public ByteBuf encrypt(ByteBuf srcBuf) throws Exception {
        ByteBuf desByteBuf = Unpooled.buffer();
        if (!encryptSaltSet) {
            byte[] salt = randomBytes(aeadCipher.getSaltSize());
            desByteBuf.writeBytes(salt);
            System.out.println("encrypt salt: " + Base64.getEncoder().encodeToString(salt));
            encodeSubKey = genSubKey(salt);
            encipher = Cipher.getInstance("AES/GCM/NoPadding");
            encryptSaltSet = true;
        }
        tcpEncrypt(srcBuf, desByteBuf);
        return desByteBuf;
    }
    @Override
    public ByteBuf decrypt(ByteBuf srcBuf) throws Exception {
        ByteBuf desByteBuf = Unpooled.buffer();
        if (!decryptSaltSet) {
            byte[] salt = new byte[aeadCipher.getSaltSize()];
            srcBuf.readBytes(salt, 0, salt.length);
            System.out.println("decrypt salt: " + Base64.getEncoder().encodeToString(salt));
            decodeSubKey = genSubKey(salt);
            decipher = Cipher.getInstance("AES/GCM/NoPadding");
            decryptSaltSet = true;
        }
        tcpDecrypt(srcBuf, desByteBuf);
        return desByteBuf;
    }

    /** AE_encrypt(key, nonce, message) => (ciphertext, tag)
     * TCP:[encrypted payload length][length tag][encrypted payload][payload tag]
     */
    private void tcpEncrypt(ByteBuf srcBuf, ByteBuf desByteBuf)
        throws InvalidAlgorithmParameterException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException {
        while (srcBuf.isReadable()) {
            // start write encrypted payload length and length tag
            int payloadLength = Math.min(srcBuf.readableBytes(), PAYLOAD_SIZE_MASK);
            byte[] payloadLengthInput = Unpooled.buffer(2).writeShort(payloadLength).array();

            // Initialize Cipher for ENCRYPT_MODE
            encipher.init(Cipher.ENCRYPT_MODE,
                new SecretKeySpec(encodeSubKey, "AES"),
                new GCMParameterSpec(TAG_LENGTH * Byte.SIZE, Arrays.copyOf(encodeNonce, NONCE_LENGTH))
            );
            // Perform Encryption
            byte[] payloadLengthOutput = encipher.doFinal(payloadLengthInput);

            desByteBuf.writeBytes(payloadLengthOutput);
            increment(encodeNonce);

            // start write encrypted payload and payload tag
            byte[] payloadInput = new byte[payloadLength];
            srcBuf.readBytes(payloadInput);

            // Initialize Cipher for ENCRYPT_MODE
            encipher.init(Cipher.ENCRYPT_MODE,
                new SecretKeySpec(encodeSubKey, "AES"),
                new GCMParameterSpec(TAG_LENGTH * Byte.SIZE, Arrays.copyOf(encodeNonce, NONCE_LENGTH))
            );

            // Perform Encryption
            byte[] payloadOutput = encipher.doFinal(payloadInput);

            desByteBuf.writeBytes(payloadOutput);
            increment(encodeNonce);
        }
    }

    /** AE_decrypt(key, nonce, ciphertext, tag) => message
     * TCP:[encrypted payload length][length tag][encrypted payload][payload tag]
     */
    private void tcpDecrypt(ByteBuf srcBuf, ByteBuf desByteBuf) throws
        InvalidAlgorithmParameterException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException {
        while (srcBuf.readableBytes() > 0) {
            // [encrypted payload length][length tag]
            if (decodeBuffer.readableBytes() == 0) {
                int lengthChunk = 2 + TAG_LENGTH - decodeBuffer.readableBytes();
                int remaining = srcBuf.readableBytes();
                if (remaining < lengthChunk) {
                    decodeBuffer.writeBytes(srcBuf, remaining);
                    return;
                } else {
                    decodeBuffer.writeBytes(srcBuf, lengthChunk);
                }

                // Initialize Cipher for DECRYPT_MODE
                decipher.init(Cipher.DECRYPT_MODE,
                    new SecretKeySpec(decodeSubKey, "AES"),
                    new GCMParameterSpec(TAG_LENGTH * Byte.SIZE, Arrays.copyOf(decodeNonce, NONCE_LENGTH))
                );


                // Perform Decryption
                byte[] payloadInput = new byte[2 + TAG_LENGTH];
                decodeBuffer.readBytes(payloadInput);
                byte[] payloadLengthOutput = decipher.doFinal(payloadInput);

                increment(decodeNonce);
                payloadLength = Unpooled.wrappedBuffer(payloadLengthOutput).readUnsignedShort();
                decodeBuffer.clear();
            }

            if (payloadLength == 0) {
                return;
            }
            int payloadChunk = payloadLength + TAG_LENGTH - decodeBuffer.readableBytes();
            int remaining = srcBuf.readableBytes();
            if (remaining < payloadChunk) {
                decodeBuffer.writeBytes(srcBuf, remaining);
                return;
            } else {
                decodeBuffer.writeBytes(srcBuf, payloadChunk);
            }

            // Initialize Cipher for DECRYPT_MODE
            decipher.init(Cipher.DECRYPT_MODE,
                new SecretKeySpec(decodeSubKey, "AES"),
                new GCMParameterSpec(TAG_LENGTH * Byte.SIZE, Arrays.copyOf(decodeNonce, NONCE_LENGTH))

            );

            // Perform Decryption
            byte[] payloadInput = new byte[payloadLength + TAG_LENGTH];
            decodeBuffer.readBytes(payloadInput);
            byte[] payloadOutput = decipher.doFinal(payloadInput);

            desByteBuf.writeBytes(payloadOutput);
            increment(decodeNonce);
            decodeBuffer.clear();
        }
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
        hkdf.init(new HKDFParameters(ssKey, salt, INFO));
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
        Aes256GcmCipher aes256GcmCipher1 = new Aes256GcmCipher(
            AeadCipherEnum.AEAD_AES_256_GCM, "abcde");
//        byte[] rawBytes = new byte[2638366];
//        Arrays.fill(rawBytes, (byte) 'd');
        byte[] rawBytes = "aaaa".getBytes();
        ByteBuf encodeOutput = aes256GcmCipher1.encrypt(Unpooled.buffer().writeBytes(rawBytes));
        System.out.println(rawBytes.length);

        Aes256GcmCipher aes256GcmCipher2 = new Aes256GcmCipher(
            AeadCipherEnum.AEAD_AES_256_GCM, "abcde");
        ByteBuf decodeOutput = aes256GcmCipher2.decrypt(encodeOutput);
        byte[] result = new byte[decodeOutput.readableBytes()];
        decodeOutput.readBytes(result);
        System.out.println(Base64.getEncoder().encodeToString(result));

        //------
        byte[] rawBytes2 = "bbbb".getBytes();
        ByteBuf encodeOutput2 = aes256GcmCipher1.encrypt(Unpooled.buffer().writeBytes(rawBytes2));
        System.out.println(encodeOutput2.readableBytes());

        ByteBuf decodeOutput2 = aes256GcmCipher2.decrypt(encodeOutput2);
        byte[] result2 = new byte[decodeOutput2.readableBytes()];
        decodeOutput2.readBytes(result2);
        System.out.println(new String(result2));
    }
}