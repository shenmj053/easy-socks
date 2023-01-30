package org.easysocks.ssserver;

import lombok.extern.slf4j.Slf4j;
import org.apache.commons.cli.CommandLine;
import org.apache.commons.cli.CommandLineParser;
import org.apache.commons.cli.DefaultParser;
import org.apache.commons.cli.Option;
import org.apache.commons.cli.Options;
import org.apache.commons.cli.ParseException;
import org.easysocks.ssserver.config.Config;
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
        Config config;
        try {
            config = ConfigReader.read(configFile);
        } catch (Exception e) {
            log.error("Server start failed, unable to load config file.");
            return;
        }
        SsServer server;
        if (commandLine.hasOption(serverOption)) {
            server = new SsRemoteServer(config);
        } else {
            server = new SsLocalClient(config);
        }
        try {
            server.start();
        } catch (Exception e) {
            log.info("Server start error {}", e.getMessage(), e);
        }
    }

}
