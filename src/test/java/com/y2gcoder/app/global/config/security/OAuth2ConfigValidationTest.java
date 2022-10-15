package com.y2gcoder.app.global.config.security;

import com.y2gcoder.app.global.config.PropertiesConfiguration;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.boot.test.context.ConfigDataApplicationContextInitializer;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.ContextConfiguration;
import org.springframework.test.context.junit.jupiter.SpringExtension;

import javax.validation.Validation;
import javax.validation.Validator;

import static org.assertj.core.api.Assertions.assertThat;

@ActiveProfiles("test")
@ExtendWith(SpringExtension.class)
@EnableConfigurationProperties(value = OAuth2Config.class)
@ContextConfiguration(initializers = ConfigDataApplicationContextInitializer.class, classes = PropertiesConfiguration.class)
class OAuth2ConfigValidationTest {
	@Autowired
	private OAuth2Config oAuth2Config;

	private static Validator propertyValidator;

	@BeforeAll
	public static void setup() {
		propertyValidator = Validation.buildDefaultValidatorFactory().getValidator();
	}

	@Test
	@DisplayName("OAuthConfig: Validation, 성공")
	void whenBindingPropertiesToValidatedBeans_thenConstrainsAreChecked() {
		assertThat(propertyValidator.validate(oAuth2Config.getOAuth2()).size()).isZero();
		assertThat(propertyValidator.validate(oAuth2Config.getAuth()).size()).isZero();
	}
}