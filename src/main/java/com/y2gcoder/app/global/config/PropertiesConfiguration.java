package com.y2gcoder.app.global.config;

import com.y2gcoder.app.global.config.security.OAuth2Config;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Configuration;

@EnableConfigurationProperties(value = {OAuth2Config.class})
@Configuration
public class PropertiesConfiguration {
}
