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
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import lombok.extern.slf4j.Slf4j;
import org.bouncycastle.crypto.digests.SHA1Digest;
import org.bouncycastle.crypto.generators.HKDFBytesGenerator;
import org.bouncycastle.crypto.params.HKDFParameters;
import org.easysocks.ssserver.common.ShadowSocksKey;

@Slf4j
public class Chacha20AeadCipher implements AeadCipher {

    private static final int PAYLOAD_SIZE_MASK = 0x3FFF;
    private static final byte[] INFO = "ss-subkey".getBytes();
    private static final int TAG_LENGTH = 16;
    private static final int NONCE_LENGTH = 12;
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

    public Chacha20AeadCipher(AeadCipherEnum aeadCipher, String password) {
        this.aeadCipher = aeadCipher;
        this.ssKey = new ShadowSocksKey(password).getEncoded();
    }

    @Override
    public ByteBuf encrypt(ByteBuf src) throws Exception {
        ByteBuf desByteBuf = Unpooled.buffer();
        if (!encryptSaltSet) {
            byte[] salt = randomBytes(aeadCipher.getSaltSize());
            desByteBuf.writeBytes(salt);
            System.out.println("encrypt salt: " + Arrays.toString(salt));
            encodeSubKey = genSubKey(salt);
            encipher = Cipher.getInstance("ChaCha20-Poly1305/None/NoPadding");
            encryptSaltSet = true;
        }
        tcpEncrypt(src, desByteBuf);
        return desByteBuf;
    }

    @Override
    public ByteBuf decrypt(ByteBuf srcBuf) throws Exception {
        ByteBuf desByteBuf = Unpooled.buffer();
        if (!decryptSaltSet) {
            byte[] salt = new byte[aeadCipher.getSaltSize()];
            srcBuf.readBytes(salt, 0, salt.length);
            System.out.println("decrypt salt: " + Arrays.toString(salt));
            decodeSubKey = genSubKey(salt);
            decipher = Cipher.getInstance("ChaCha20-Poly1305/None/NoPadding");
            decryptSaltSet = true;
        }
        tcpDecrypt(srcBuf, desByteBuf);
        return desByteBuf;
    }

    /**
     * AE_encrypt(key, nonce, message) => (ciphertext, tag) TCP:[encrypted payload length][length
     * tag][encrypted payload][payload tag]
     */
    private void tcpEncrypt(ByteBuf srcBuf, ByteBuf desByteBuf)
        throws InvalidAlgorithmParameterException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException {
        while (srcBuf.isReadable()) {
            // start write encrypted payload length and length tag
            int payloadLength = Math.min(srcBuf.readableBytes(), PAYLOAD_SIZE_MASK);
            byte[] payloadLengthInput = Unpooled.buffer(2).writeShort(payloadLength).array();

            // Initialize Cipher for ENCRYPT_MODE
            encipher.init(Cipher.ENCRYPT_MODE,
                new SecretKeySpec(encodeSubKey, "ChaCha20"),
                new IvParameterSpec(Arrays.copyOf(encodeNonce, NONCE_LENGTH))
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
                new SecretKeySpec(encodeSubKey, "ChaCha20"),
                new IvParameterSpec(Arrays.copyOf(encodeNonce, NONCE_LENGTH))
            );

            // Perform Encryption
            byte[] payloadOutput = encipher.doFinal(payloadInput);

            desByteBuf.writeBytes(payloadOutput);
            increment(encodeNonce);
        }
    }

    /**
     * AE_decrypt(key, nonce, ciphertext, tag) => message TCP:[encrypted payload length][length
     * tag][encrypted payload][payload tag]
     */
    private void tcpDecrypt(ByteBuf srcBuf, ByteBuf desByteBuf)
        throws InvalidAlgorithmParameterException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException {
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

                // Initialize Cipher for ENCRYPT_MODE
                decipher.init(Cipher.DECRYPT_MODE,
                    new SecretKeySpec(decodeSubKey, "ChaCha20"),
                    new IvParameterSpec(Arrays.copyOf(decodeNonce, NONCE_LENGTH))
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

            // Initialize Cipher for ENCRYPT_MODE
            decipher.init(Cipher.DECRYPT_MODE,
                new SecretKeySpec(decodeSubKey, "ChaCha20"),
                new IvParameterSpec(Arrays.copyOf(decodeNonce, NONCE_LENGTH))
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

    private static byte[] randomBytes(int size) {
        byte[] bytes = new byte[size];
        new SecureRandom().nextBytes(bytes);
        return bytes;
    }

    /**
     * HKDF_SHA1 is a function that takes a secret key, a non-secret salt, an info string, and
     * produces a subkey that is cryptographically strong even if the input secret key is weak.
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
        String plainText = "abcd";
        Chacha20AeadCipher aes256GcmCipher1 = new Chacha20AeadCipher(
            AeadCipherEnum.AEAD_CHACHA20_POLY1305, "aes-256-gcm");
        ByteBuf res = aes256GcmCipher1.encrypt(Unpooled.buffer().writeBytes(plainText.getBytes()));
        byte[] resBytes = new byte[res.readableBytes()];
        res.getBytes(0, resBytes);
        System.out.println("EEEEncrypted Text : " + Base64.getEncoder().encodeToString(resBytes));

        Chacha20AeadCipher aes256GcmCipher2 = new Chacha20AeadCipher(
            AeadCipherEnum.AEAD_CHACHA20_POLY1305, "aes-256-gcm");
        ByteBuf decodeOutput = aes256GcmCipher2.decrypt(res);
        byte[] decodeOutputBytes = new byte[decodeOutput.readableBytes()];
        decodeOutput.readBytes(decodeOutputBytes);
        System.out.println("DDDncrypted Text : " + new String(decodeOutputBytes));
    }
}
