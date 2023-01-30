package org.easysocks.ssserver.config;

import com.fasterxml.jackson.databind.ObjectMapper;
import java.io.InputStream;
import java.nio.file.Path;
import java.nio.file.Paths;
import lombok.extern.slf4j.Slf4j;

@Slf4j
public class ConfigReader {
    private ConfigReader() {}
    public static Config read(String configFile) throws Exception {
        ObjectMapper mapper = new ObjectMapper();
        try {
            Path configPath = Paths.get(System.getProperty("user.dir"), configFile);
            Config config = mapper.readValue(configPath.toFile(), Config.class);

            log.info("Use customized config: {}", config.toString());
            return config;
        } catch (Exception ex) {
            ClassLoader classLoader = ConfigReader.class.getClassLoader();
            InputStream configStream= classLoader.getResourceAsStream("config.json");
            Config config = mapper.readValue(configStream, Config.class);
            log.warn("customized config file not found, Use default config: {}",
                config.toString());
            return config;
        }
    }
}
