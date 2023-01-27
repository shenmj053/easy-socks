package org.easysocks.ssserver.config;

import com.fasterxml.jackson.databind.ObjectMapper;
import io.netty.util.internal.logging.InternalLogger;
import io.netty.util.internal.logging.InternalLoggerFactory;
import java.io.InputStream;
import java.nio.file.Path;
import java.nio.file.Paths;
import lombok.extern.slf4j.Slf4j;

@Slf4j
public class ConfigReader {

    public Config read(String configFile) {
        ObjectMapper mapper = new ObjectMapper();
        try {
            Path configPath = Paths.get(System.getProperty("user.dir"), configFile);
            Config config = mapper.readValue(configPath.toFile(), Config.class);

            log.info("Use customized config: {}", config.toString());
            return config;
        } catch (Exception ex) {
            try {
                InputStream configStream= getDefaultConfig();
                Config config = mapper.readValue(configStream, Config.class);
                log.info("Use default config: {}", config.toString());
                return config;
            } catch (Exception e) {
                log.info("Load default config failed, ", e);
                return new Config();
            }
        }
    }

    private InputStream getDefaultConfig() {

        ClassLoader classLoader = getClass().getClassLoader();
        InputStream inputStream = classLoader.getResourceAsStream("config.json");

        if (inputStream == null) {
            throw new IllegalArgumentException("default config file not found! ");
        } else {
            return inputStream;
        }
    }
}
