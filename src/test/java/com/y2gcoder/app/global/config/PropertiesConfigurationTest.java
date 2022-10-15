package com.y2gcoder.app.global.config;

import com.y2gcoder.app.global.config.security.OAuth2Config;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.boot.test.context.ConfigDataApplicationContextInitializer;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.ContextConfiguration;
import org.springframework.test.context.junit.jupiter.SpringExtension;

import static org.assertj.core.api.Assertions.assertThat;

@ActiveProfiles("test")
@ExtendWith(SpringExtension.class)
@EnableConfigurationProperties(value = OAuth2Config.class)
@ContextConfiguration(initializers = ConfigDataApplicationContextInitializer.class, classes = PropertiesConfiguration.class)
class PropertiesConfigurationTest {
	@Autowired
	private OAuth2Config oAuth2Config;

	@Test
	@DisplayName("OAuth2Config: 프로퍼티 테스트, 성공")
	void bindingProperties_Normal_Success() {
		//given
		//when
		//then
		assertThat(oAuth2Config.getOAuth2().getAuthorizedRedirectUris()).contains("http://localhost:3000/oauth2/redirect");
		assertThat(oAuth2Config.getAuth().getTokenSecret()).isNotEmpty();
		assertThat(oAuth2Config.getAuth().getRefreshCookieKey()).isEqualTo("refreshtoken");
		assertThat(oAuth2Config.getAuth().getAccessTokenValidityInMs()).isNotZero().isPositive();
		assertThat(oAuth2Config.getAuth().getRefreshTokenValidityInMs()).isNotZero().isPositive();
	}
}