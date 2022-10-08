package com.y2gcoder.app.global.config.security;

import lombok.Data;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.context.annotation.Configuration;

import java.util.ArrayList;
import java.util.List;

@ConfigurationProperties(prefix = "app")
@Configuration
public class OAuth2Config {
	private final Auth auth = new Auth();
	private final OAuth2 oAuth2 = new OAuth2();

	@Data
	public static class Auth {
		private String tokenSecret;
		private long accessTokenValidityInMs;
		private long refreshTokenValidityInMs;
	}

	public static class OAuth2 {
		private List<String> authorizedRedirectUris = new ArrayList<>();

		public List<String> getAuthorizedRedirectUris() {
			return authorizedRedirectUris;
		}

		public OAuth2 authorizedRedirectUris(List<String> authorizedRedirectUris) {
			this.authorizedRedirectUris = authorizedRedirectUris;
			return this;
		}
	}

	public Auth getAuth() {
		return auth;
	}

	public OAuth2 getoAuth2() {
		return oAuth2;
	}
}
