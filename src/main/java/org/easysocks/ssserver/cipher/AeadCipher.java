package org.easysocks.ssserver.cipher;

import io.netty.buffer.ByteBuf;

public interface AeadCipher {
    ByteBuf encrypt(ByteBuf src) throws Exception;
    ByteBuf decrypt(ByteBuf src) throws Exception;
}
