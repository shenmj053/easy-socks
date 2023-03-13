package org.easysocks.ssserver.common;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import javax.crypto.SecretKey;
import lombok.extern.slf4j.Slf4j;

/**
 * Shadowsocks key generator
 */
@Slf4j
public class ShadowSocksKey implements SecretKey {
	private static final long serialVersionUID = 1L;
	private final static int KEY_LENGTH = 32;
	private final byte[] key;


	public ShadowSocksKey(String password) {
		key = init(password);
	}

	private byte[] init(String password) {
		MessageDigest md;
		byte[] keys = new byte[KEY_LENGTH];
		byte[] temp = null;
		byte[] hash = null;
		byte[] passwordBytes;
		int i = 0;

		try {
			md = MessageDigest.getInstance("MD5");
			passwordBytes = password.getBytes(StandardCharsets.UTF_8);
		} catch (Exception e) {
			log.error("init error", e);
			return null;
		}

		while (i < keys.length) {
			if (i == 0) {
				hash = md.digest(passwordBytes);
				temp = new byte[passwordBytes.length + hash.length];
			} else {
				System.arraycopy(hash, 0, temp, 0, hash.length);
				System.arraycopy(passwordBytes, 0, temp, hash.length, passwordBytes.length);
				hash = md.digest(temp);
			}
			System.arraycopy(hash, 0, keys, i, hash.length);
			i += hash.length;
		}
		return keys;
	}

	@Override
	public String getAlgorithm() {
		return "shadowsocks";
	}

	@Override
	public String getFormat() {
		return "RAW";
	}

	@Override
	public byte[] getEncoded() {
		return key;
	}
}
