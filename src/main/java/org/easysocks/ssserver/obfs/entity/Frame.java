package org.easysocks.ssserver.obfs.entity;

public class Frame {
    int idx;
    int len;
    short[] buf = new short[2];
}
