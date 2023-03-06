package org.easysocks.ssserver.config;

import com.fasterxml.jackson.annotation.JsonProperty;
import lombok.Data;

@Data
public class SsConfig {
    @JsonProperty("server_address")
    private String serverAddress;

    @JsonProperty("server_port")
    private Integer serverPort;

    @JsonProperty("password")
    private String password;

    @JsonProperty("method")
    private String method;

    @JsonProperty("client_port")
    private Integer clientPort;

    @JsonProperty("obfs")
    private String obfs;

    @JsonProperty("obfs_host")
    private String obfsHost;

    @JsonProperty("server_key")
    private String serverKey;
}
