package org.easysocks.ssserver.obfs.entity;

struct tls_client_hello {
    char  content_type;
    short version;
    short len;

    char  handshake_type;
    char  handshake_len_1;
    short handshake_len_2;
    short handshake_version;

    int   random_unix_time;
    char  random_bytes[28];
    char  session_id_len;
    char  session_id[32];
    short cipher_suites_len;
    char  cipher_suites[56];
    char  comp_methods_len;
    char  comp_methods[1];
    short ext_len;
    } __attribute__((packed, aligned(1)));

    struct tls_ext_server_name {
    short ext_type;
    short ext_len;
    short server_name_list_len;
    char  server_name_type;
    short server_name_len;
    // char server_name[server_name_len];
    } __attribute__((packed, aligned(1)));

    struct tls_ext_session_ticket {
    short session_ticket_type;
    short session_ticket_ext_len;
    // char  session_ticket[session_ticket_ext_len];
    } __attribute__((packed, aligned(1)));

    struct tls_ext_others {
    short ec_point_formats_ext_type;
    short ec_point_formats_ext_len;
    char  ec_point_formats_len;
    char  ec_point_formats[3];

    short elliptic_curves_type;
    short elliptic_curves_ext_len;
    short elliptic_curves_len;
    char  elliptic_curves[8];

    short sig_algos_type;
    short sig_algos_ext_len;
    short sig_algos_len;
    char  sig_algos[30];

    short encrypt_then_mac_type;
    short encrypt_then_mac_ext_len;

    short extended_master_secret_type;
    short extended_master_secret_ext_len;
    } __attribute__((packed, aligned(1)));

    struct tls_server_hello {
    char  content_type;
    short version;
    short len;

    char  handshake_type;
    char  handshake_len_1;
    short handshake_len_2;
    short handshake_version;

    int   random_unix_time;
    char  random_bytes[28];
    char  session_id_len;
    char  session_id[32];
    short cipher_suite;
    char  comp_method;
    short ext_len;

    short ext_renego_info_type;
    short ext_renego_info_ext_len;
    char  ext_renego_info_len;

    short extended_master_secret_type;
    short extended_master_secret_ext_len;

    short ec_point_formats_ext_type;
    short ec_point_formats_ext_len;
    char  ec_point_formats_len;
    char  ec_point_formats[1];
    } __attribute__((packed, aligned(1)));

    struct tls_change_cipher_spec {
    char  content_type;
    short version;
    short len;
    char  msg;
    } __attribute__((packed, aligned(1)));

    struct tls_encrypted_handshake {
    char  content_type;
    short version;
    short len;
    // char  msg[len];
    } __attribute__((packed, aligned(1)));

    typedef struct frame {
    short idx;
    short len;
    char  buf[2];
    } frame_t;

    extern obfs_para_t *obfs_tls;

    #endif
