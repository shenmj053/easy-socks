package org.easysocks.ssserver.config;

import com.fasterxml.jackson.databind.ObjectMapper;
import java.io.InputStream;
import java.nio.file.Path;
import java.nio.file.Paths;
import lombok.extern.slf4j.Slf4j;

@Slf4j
public class ConfigReader {
    private ConfigReader() {}
    public static SsConfig read(String configFile) throws Exception {
        ObjectMapper mapper = new ObjectMapper();
        try {
            Path configPath = Paths.get(System.getProperty("user.dir"), configFile);
            SsConfig ssConfig = mapper.readValue(configPath.toFile(), SsConfig.class);

            log.info("Use customized config: {}", ssConfig.toString());
            return ssConfig;
        } catch (Exception ex) {
            ClassLoader classLoader = ConfigReader.class.getClassLoader();
            InputStream configStream= classLoader.getResourceAsStream("config.json");
            SsConfig ssConfig = mapper.readValue(configStream, SsConfig.class);
            log.warn("customized config file not found, Use default config: {}",
                ssConfig.toString());
            return ssConfig;
        }
    }
}
