# easy-socks
It is just a toy java implementation of Shadowsocks, base on netty4 framework.

## build
  `./mvnw package`

## ssConfig
```json
{
  "server_address": "remote server public ip address",
  "server_port": 5679,
  "client_port": 1235,
  "password": "super secret",
  "method": "aes-256-gcm"
}
```

## run
- as client
  `java -jar easy-socks-0.0.1-SNAPSHOT-client-exec.jar -c ssConfig.json`
- as server
  `java -jar easy-socks-0.0.1-SNAPSHOT-server-exec.jar -c ssConfig.json --server`

## verify usage
run command line on local host
`curl -x socks5h://0.0.0.0:1234 -v -k -X GET https://www.google.com.hk`




