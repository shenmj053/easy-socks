package org.easysocks.ssserver.obfs.entity;

import io.netty.buffer.ByteBuf;

public class ObfsState {
    int obfsStage;
    int deobfsStage;
    ByteBuf buf;
    Frame extra;

}
