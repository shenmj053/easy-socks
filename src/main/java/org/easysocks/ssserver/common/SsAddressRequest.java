package org.easysocks.ssserver.common;

import io.netty.buffer.ByteBuf;
import io.netty.handler.codec.socks.SocksAddressType;
import io.netty.util.CharsetUtil;
import io.netty.util.NetUtil;
import java.net.IDN;

public final class SsAddressRequest {
    private final SocksAddressType socksAddressType;
    private final String host;
    private final int port;

    public SsAddressRequest(SocksAddressType socksAddressType, String host, int port) {
        if (socksAddressType == null) {
            throw new NullPointerException("addressType");
        } else if (host == null) {
            throw new NullPointerException("host");
        } else {
            switch(socksAddressType) {
                case IPv4:
                    if (!NetUtil.isValidIpV4Address(host)) {
                        throw new IllegalArgumentException(host + " is not a valid IPv4 address");
                    }
                    break;
                case IPv6:
                    if (!NetUtil.isValidIpV6Address(host)) {
                        throw new IllegalArgumentException(host + " is not a valid IPv6 address");
                    }
                    break;
                case DOMAIN:
                    if (IDN.toASCII(host).length() > 255) {
                        throw new IllegalArgumentException(host + " IDN: " + IDN.toASCII(host) + " exceeds 255 char limit");
                    }
                    break;
                case UNKNOWN:
                default:
            }

            if (port > 0 && port < 65536) {
                this.socksAddressType = socksAddressType;
                this.host = IDN.toASCII(host);
                this.port = port;
            } else {
                throw new IllegalArgumentException(port + " is not in bounds 0 < x < 65536");
            }
        }
    }


    public SocksAddressType socksAddressType() {
        return this.socksAddressType;
    }

    public String host() {
        return IDN.toUnicode(this.host);
    }

    public int port() {
        return this.port;
    }

    public void encodeAsByteBuf(ByteBuf byteBuf) {
        byteBuf.writeByte(this.socksAddressType.byteValue());
        switch(this.socksAddressType) {
            case IPv4:
            case IPv6:
                byteBuf.writeBytes(NetUtil.createByteArrayFromIpAddressString(this.host));
                byteBuf.writeShort(this.port);
                break;
            case DOMAIN:
                byteBuf.writeByte(this.host.length());
                byteBuf.writeBytes(this.host.getBytes(CharsetUtil.US_ASCII));
                byteBuf.writeShort(this.port);
                break;
            default:
        }
    }

    public static SsAddressRequest getSsAddressRequest(ByteBuf byteBuf) {
        SsAddressRequest request = null;
        SocksAddressType addressType = SocksAddressType.valueOf(byteBuf.readByte());
        String host;
        int port;
        switch (addressType) {
            case IPv4: {
                host = SocksCommonUtils.intToIp(byteBuf.readInt());
                port = byteBuf.readUnsignedShort();
                request = new SsAddressRequest(addressType, host, port);
                break;
            }
            case IPv6: {
                byte[] bytes = new byte[16];
                byteBuf.readBytes(bytes);
                host = SocksCommonUtils.ipv6toStr(bytes);
                port = byteBuf.readUnsignedShort();
                request = new SsAddressRequest(addressType, host, port);
                break;
            }
            case DOMAIN: {
                int fieldLength = byteBuf.readByte();
                host = SocksCommonUtils.readUsAscii(byteBuf, fieldLength);
                port = byteBuf.readUnsignedShort();
                request = new SsAddressRequest(addressType, host, port);
                break;
            }
            case UNKNOWN:
                break;
            default:
        }
        return request;
    }
}