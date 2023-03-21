package org.easysocks.ssserver;

import java.util.Optional;
import lombok.extern.slf4j.Slf4j;
import org.apache.commons.cli.CommandLine;
import org.apache.commons.cli.CommandLineParser;
import org.apache.commons.cli.DefaultParser;
import org.apache.commons.cli.Option;
import org.apache.commons.cli.Options;
import org.apache.commons.cli.ParseException;
import org.easysocks.ssserver.cipher.AeadCipher;
import org.easysocks.ssserver.cipher.AeadCipherEnum;
import org.easysocks.ssserver.cipher.AeadCipherFactory;
import org.easysocks.ssserver.config.SsConfig;
import org.easysocks.ssserver.config.ConfigReader;
import org.easysocks.ssserver.local.SsLocalClient;
import org.easysocks.ssserver.remote.SsRemoteServer;

@Slf4j
public class SsApplication {
    public static void main(String[] args) throws ParseException {
        Options options = new Options();
        Option serverOption = new Option(
            "s",
            "server",
            false,
            "run as server");
        options.addOption(serverOption);

        Option configOption = new Option(
            "c",
            "config",
            true,
            "config file");
        options.addOption(configOption);

        CommandLineParser parser = new DefaultParser();
        CommandLine commandLine;
        try {
            commandLine = parser.parse(options, args);
        } catch (ParseException e) {
            log.warn("\n"
                + "Usage: java -jar <jar file path>\n"
                + "Options: \n"
                + "-s, --server     run as remote server\n"
                + "-c, --config     customized config file name in your workdir\n");
            return;
        }

        String configFile = commandLine.getOptionValue(configOption);
        SsConfig ssConfig;
        try {
            ssConfig = ConfigReader.read(configFile);
        } catch (Exception e) {
            log.error("Server start failed, unable to load config file.");
            return;
        }

        Optional<AeadCipherEnum> aeadCipherEnumOptional = AeadCipherEnum.parse(ssConfig.getMethod());
        if (aeadCipherEnumOptional.isEmpty()) {
            log.error("Invalid AEAD cipher method {}", ssConfig.getMethod());
            return;
        }

        SsServer server;
        if (commandLine.hasOption(serverOption)) {
            server = new SsRemoteServer(ssConfig);
        } else {
            server = new SsLocalClient(ssConfig);
        }
        try {
            server.start();
        } catch (Exception e) {
            log.info("Server start error {}", e.getMessage(), e);
        }
    }

}
