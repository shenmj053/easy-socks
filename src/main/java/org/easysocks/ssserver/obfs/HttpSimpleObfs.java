package org.easysocks.ssserver.obfs;

import com.google.common.primitives.Bytes;
import io.netty.buffer.ByteBuf;
import io.netty.buffer.Unpooled;
import io.netty.channel.ChannelHandlerContext;
import io.netty.handler.codec.MessageToMessageCodec;
import java.time.LocalDateTime;
import java.time.ZoneId;
import java.time.ZoneOffset;
import java.time.format.DateTimeFormatter;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Locale;
import java.util.Objects;
import java.util.Random;
import lombok.extern.slf4j.Slf4j;
import org.easysocks.ssserver.config.SsConfig;

@Slf4j
public class HttpSimpleObfs extends MessageToMessageCodec<Object, Object> {
    String[] userAgents = {"Mozilla/5.0 (Windows NT 6.3; WOW64; rv:40.0) Gecko/20100101 Firefox/40.0",
        "Mozilla/5.0 (Windows NT 6.3; WOW64; rv:40.0) Gecko/20100101 Firefox/44.0",
        "Mozilla/5.0 (Windows NT 6.1) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/41.0.2228.0 Safari/537.36",
        "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/535.11 (KHTML, like Gecko) Ubuntu/11.10 Chromium/27.0.1453.93 Chrome/27.0.1453.93 Safari/537.36",
        "Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:35.0) Gecko/20100101 Firefox/35.0",
        "Mozilla/5.0 (compatible; WOW64; MSIE 10.0; Windows NT 6.2)",
        "Mozilla/5.0 (Windows; U; Windows NT 6.1; en-US) AppleWebKit/533.20.25 (KHTML, like Gecko) Version/5.0.4 Safari/533.20.27",
        "Mozilla/4.0 (compatible; MSIE 7.0; Windows NT 6.3; Trident/7.0; .NET4.0E; .NET4.0C)",
        "Mozilla/5.0 (Windows NT 6.3; Trident/7.0; rv:11.0) like Gecko",
        "Mozilla/5.0 (Linux; Android 4.4; Nexus 5 Build/BuildID) AppleWebKit/537.36 (KHTML, like Gecko) Version/4.0 Chrome/30.0.0.0 Mobile Safari/537.36",
        "Mozilla/5.0 (iPad; CPU OS 5_0 like Mac OS X) AppleWebKit/534.46 (KHTML, like Gecko) Version/5.1 Mobile/9A334 Safari/7534.48.3",
        "Mozilla/5.0 (iPhone; CPU iPhone OS 5_0 like Mac OS X) AppleWebKit/534.46 (KHTML, like Gecko) Version/5.1 Mobile/9A334 Safari/7534.48.3"
    };
    private final boolean ssClient;
    private final SsConfig ssConfig;
    private boolean hasSentHeader = false;
    private boolean hasReceivedHeader = false;
    private final String[] hosts;
    private final ByteBuf receiveBuffer = Unpooled.buffer(65535);

    public HttpSimpleObfs(SsConfig ssConfig, boolean ssClient) {
        this.ssConfig = ssConfig;
        this.ssClient = ssClient;
        this.hosts = ssConfig.getObfsParam().split(";")[0].split("=")[1].split(",");
    }

    @Override
    protected void encode(ChannelHandlerContext ctx, Object msg, List<Object> out) {
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
    protected void decode(ChannelHandlerContext ctx, Object msg, List<Object> out) {
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

    private ByteBuf clientEncode(ByteBuf buf) {
        if (hasSentHeader) {
            buf.retain();
            return buf;
        }
        byte[] headData;
        // headSize = default Encryption IV + default head len
        int headSize = 48 + 30;
        if (buf.readableBytes() - headSize > 64) {
            headData = new byte[headSize + new Random().nextInt(65)];
        } else {
            headData = new byte[buf.readableBytes()];
        }
        buf.readBytes(headData);

        ByteBuf httpHeadBuf = Unpooled.buffer(65535);
        httpHeadBuf.writeBytes("GET / ".getBytes());
        httpHeadBuf.writeBytes(encodeHead(headData).getBytes());
        httpHeadBuf.writeBytes(" HTTP/1.1\r\n".getBytes());
        httpHeadBuf.writeBytes(("Host: " + hosts[new Random().nextInt(hosts.length)] + "\r\n").getBytes());

        httpHeadBuf.writeBytes("User-Agent: ".getBytes());
        httpHeadBuf.writeBytes((userAgents[new Random().nextInt(userAgents.length)] + "\r\n").getBytes());

        httpHeadBuf.writeBytes("Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8\r\n".getBytes());
        httpHeadBuf.writeBytes("Accept-Language: en-US,en;q=0.8\r\n".getBytes());
        httpHeadBuf.writeBytes("Accept-Encoding: gzip, deflate\r\n".getBytes());
        httpHeadBuf.writeBytes("Connection: keep-alive\r\n\r\n".getBytes());

        httpHeadBuf.writeBytes(buf);
        hasSentHeader = true;
        return httpHeadBuf;
    }

    private ByteBuf clientDecode(ByteBuf buf) {
        if (hasReceivedHeader) {
            buf.retain();
            return buf;
        }

        receiveBuffer.writeBytes(buf);
        byte[] receiveBufferArray = new byte[receiveBuffer.readableBytes()];
        receiveBuffer.getBytes(0, receiveBufferArray);
        int index = Bytes.indexOf(receiveBufferArray, "\r\n\r\n".getBytes());
        if (index >= 0) {
            ByteBuf desBuf = Unpooled.buffer(receiveBufferArray.length - index - 4);
            desBuf.writeBytes(receiveBuffer, index + 4, receiveBufferArray.length - index - 4);
            hasReceivedHeader = true;
            receiveBuffer.clear();
            return desBuf;
        }
        return Unpooled.buffer(0);
    }

    private ByteBuf serverEncode(ByteBuf buf) {
        if (hasSentHeader) {
            buf.retain();
            return buf;
        }
        ByteBuf httpHeadBuf = Unpooled.buffer(65535);
        httpHeadBuf.writeBytes("HTTP/1.1 200 OK\r\n".getBytes());
        httpHeadBuf.writeBytes("Connection: keep-alive\r\n".getBytes());
        httpHeadBuf.writeBytes("Content-Encoding: gzip\r\n".getBytes());
        httpHeadBuf.writeBytes("Content-Type: text/html\r\n".getBytes());
        String now = DateTimeFormatter
            .ofPattern("EEE, dd MMM yyyy HH:mm:ss z", Locale.ENGLISH)
            .withZone(ZoneId.of("GMT"))
            .format(LocalDateTime.now(ZoneOffset.UTC));
        httpHeadBuf.writeBytes((now + "\r\n").getBytes());
        httpHeadBuf.writeBytes("Server: nginx\r\n".getBytes());
        httpHeadBuf.writeBytes("Vary: Accept-Encoding\r\n\r\n".getBytes());
        httpHeadBuf.writeBytes(buf);
        hasSentHeader = true;
        return httpHeadBuf;
    }

    private ByteBuf serverDecode(ByteBuf buf) {
        if (hasReceivedHeader) {
            buf.retain();
            return buf;
        }
        receiveBuffer.writeBytes(buf);
        if (receiveBuffer.readableBytes() > 10) {
            byte[] httpMethod = new byte[3];
            receiveBuffer.getBytes(0, httpMethod);
            if (Arrays.equals(httpMethod, "GET".getBytes())) {
                if (receiveBuffer.readableBytes() > 65536) {
                    log.warn("http_simple server decode: over size");
                    return decodeNotMatchReturn();
                }
            } else {
                // not http header
                log.info("http_simple server decode: not match begin");
                return decodeNotMatchReturn();
            }
        } else {
            return Unpooled.buffer(0);
        }

        byte[] receiveBufferArray = new byte[receiveBuffer.readableBytes()];
        receiveBuffer.getBytes(0, receiveBufferArray);
        int index = Bytes.indexOf(receiveBufferArray, "\r\n\r\n".getBytes());
        if (index >= 0) {
            byte[] hostBytes = getHostFromHttpHeader(receiveBufferArray);
            String host = new String(hostBytes).split(":")[0];
            if (!Arrays.asList(hosts).contains(host)) {
                log.info("http_simple server decode: not match host");
                return decodeNotMatchReturn();
            }

            byte[] headerBytes = getDataFromHttpHeader(receiveBufferArray);
            if (headerBytes.length < 4) {
                log.info("http_simple server decode: data in header too short");
                return decodeErrorReturn();
            }
            ByteBuf resultBuf = Unpooled.buffer(receiveBuffer.readableBytes());
            resultBuf.writeBytes(headerBytes);
            if (receiveBufferArray.length > index + 4) {
                resultBuf.writeBytes(receiveBuffer, index + 4, receiveBuffer.readableBytes() - index - 4);
            }
            if (resultBuf.readableBytes() > 13) {
                hasReceivedHeader = true;
                receiveBuffer.clear();
                return resultBuf;
            }
            log.info("http_simple server decode: header + data too short");
            return decodeNotMatchReturn();
        }
        return Unpooled.buffer(0);
    }

    private static String encodeHead(byte[] header) {
        StringBuilder hexString = new StringBuilder(3 * header.length);
        for (byte h : header) {
            hexString.append('%');
            String hex = Integer.toHexString(0xff & h);
            if (hex.length() == 1) {
                hexString.append('0');
            }
            hexString.append(hex);
        }
        return hexString.toString();
    }

    private static byte[] getDataFromHttpHeader(byte[] header) {
        int index = Bytes.indexOf(header, "\r\n".getBytes());
        if (index >= 0) {
            byte[] firstLine = Arrays.copyOfRange(header, 0, index);
            ByteBuf resultBuf = Unpooled.buffer(256);
            int i = 0;
            while (i < firstLine.length) {
                if (firstLine[i] == (byte)'%') {
                    resultBuf.writeByte(((Character.digit(firstLine[i+1], 16) << 4)
                        + Character.digit(firstLine[i+2], 16)));
                    i += 3;
                } else {
                    i++;
                }
            }
            byte[] result = new byte[resultBuf.readableBytes()];
            resultBuf.readBytes(result);
            return result;
            }
        return new byte[0];
    }

    ByteBuf decodeErrorReturn() {
        hasReceivedHeader = true;
        hasSentHeader = true;
        receiveBuffer.clear();
        ByteBuf result = Unpooled.buffer(2048);
        byte[] r = new byte[2048];
        Arrays.fill(r, (byte)'E');
        result.writeBytes(r);
        return result;
    }

    ByteBuf decodeNotMatchReturn() {
        hasReceivedHeader = true;
        hasSentHeader = true;
        if (Objects.equals(ssConfig.getObfs(), "http-simple")) {
            receiveBuffer.clear();
            ByteBuf result = Unpooled.buffer(2048);
            byte[] r = new byte[2048];
            Arrays.fill(r, (byte) 'E');
            result.writeBytes(r);
            return result;
        } else {
            ByteBuf result = receiveBuffer.copy();
            receiveBuffer.clear();
            return result;
        }
    }

    byte[] getHostFromHttpHeader(byte[] header) {
        int startIndex = Bytes.indexOf(header, "Host: ".getBytes());
        if (startIndex >= 0) {
            int endIndex = Bytes.indexOf(Arrays.copyOfRange(header, startIndex, header.length), "\r\n".getBytes());
            if (endIndex > 0) {
                return Arrays.copyOfRange(header, startIndex + 6, startIndex + endIndex);
            }
        }
        return new byte[0];
    }

    public static void main(String[] args) {
        SsConfig ssConfig = new SsConfig();
        ssConfig.setObfs("http-simple");
        ssConfig.setObfsParam("obfs-host=www.bing.com,www.bing.com");

        HttpSimpleObfs httpSimpleObfs = new HttpSimpleObfs(ssConfig, true);
        ByteBuf raw = Unpooled.buffer(5);
        raw.writeBytes("21:26:32,516 |-INFO in ch.qos.logback.classic.joran.JoranConfigurator@1d8bd0de - Registering current configuration as safe fallback point".getBytes());
        ByteBuf encoded = httpSimpleObfs.clientEncode(raw);

        HttpSimpleObfs httpSimpleObfs2 = new HttpSimpleObfs(ssConfig, false);
        ByteBuf decoded = httpSimpleObfs2.serverDecode(encoded);
        byte[] r = new byte[decoded.readableBytes()];
        decoded.readBytes(r);
        System.out.println(new String(r));


        HttpSimpleObfs httpSimpleObfs3 = new HttpSimpleObfs(ssConfig, false);
        ByteBuf raw1 = Unpooled.buffer(5);
        raw1.writeBytes("21:26:32,516 |-INFO in ch.qos.logback.classic.joran.JoranConfigurator@1d8bd0de - Registering current configuration as safe fallback point".getBytes());
        ByteBuf encoded1 = httpSimpleObfs3.serverEncode(raw1);

        HttpSimpleObfs httpSimpleObfs4 = new HttpSimpleObfs(ssConfig, true);
        ByteBuf decoded1 = httpSimpleObfs4.clientDecode(encoded1);
        byte[] r1 = new byte[decoded1.readableBytes()];
        decoded1.readBytes(r1);
        System.out.println(new String(r1));


    }
}
