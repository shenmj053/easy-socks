package org.easysocks.ssserver.common;

import io.netty.buffer.ByteBuf;
import io.netty.util.CharsetUtil;
import io.netty.util.internal.StringUtil;

/**
 * most code copy from io.netty.handler.codec.socks.SocksCommonUtils
 */
public class SocksCommonUtils {
    /**
     * A constructor to stop this class being constructed.
     */
    private SocksCommonUtils() {
        // NOOP
    }

    private static final char ipv6hextetSeparator = ':';

    /**
     * Converts numeric IPv4 to string format.
     */
    public static String intToIp(int i) {
        return String.valueOf(i >> 24 & 0xff) + '.' +
            (i >> 16 & 0xff) + '.' +
            (i >> 8 & 0xff) + '.' +
            (i & 0xff);
    }

    /**
     * Converts numeric IPv6 to standard (non-compressed) format.
     */
    public static String ipv6toStr(byte[] src) {
        assert src.length == 16;
        StringBuilder sb = new StringBuilder(39);
        ipv6toStr(sb, src, 0, 8);
        return sb.toString();
    }

    private static void ipv6toStr(StringBuilder sb, byte[] src, int fromHextet, int toHextet) {
        int i;
        toHextet --;
        for (i = fromHextet; i < toHextet; i++) {
            appendHextet(sb, src, i);
            sb.append(ipv6hextetSeparator);
        }

        appendHextet(sb, src, i);
    }

    private static void appendHextet(StringBuilder sb, byte[] src, int i) {
        StringUtil.toHexString(sb, src, i << 1, 2);
    }

    public static String readUsAscii(ByteBuf buffer, int length) {
        String s = buffer.toString(buffer.readerIndex(), length, CharsetUtil.US_ASCII);
        buffer.skipBytes(length);
        return s;
    }
}