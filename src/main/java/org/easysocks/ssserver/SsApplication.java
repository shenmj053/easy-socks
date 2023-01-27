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
        Option option = new Option("s", "server", false, "run as server");
        options.addOption(option);

        option = new Option("c", "config", true, "config file");
        options.addOption(option);

        CommandLineParser parser = new DefaultParser();
        CommandLine commandLine = parser.parse(options, args);

        String configFile = commandLine.getOptionValue("config", "");
        Config config = new ConfigReader().read(configFile);
        SsServer server;
        if (commandLine.hasOption("server")) {
            server = new SsRemoteServer(config);
            log.info("Run ss server");
        } else {
            server = new SsLocalClient(config);
            log.info("Run ss client");
        }
        try {
            server.start();
        } catch (Exception e) {
            e.printStackTrace();
            server.stop();
            System.exit(1);
        }
    }

}
