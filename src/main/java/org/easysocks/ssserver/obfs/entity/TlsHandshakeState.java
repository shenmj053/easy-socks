package org.easysocks.ssserver.obfs.entity;

public enum TlsHandshakeState {
    NOT_STARTED,
    CLIENT_HELLO,
    SERVER_HELLO_CHANGE_CIPHER_SPEC_FINISH,
    CLIENT_HELLO_CHANGE_CIPHER_SPEC_FINISH;
}
