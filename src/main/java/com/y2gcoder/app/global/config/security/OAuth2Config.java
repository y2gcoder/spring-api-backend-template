package com.y2gcoder.app.global.config.security;

import lombok.Getter;
import lombok.RequiredArgsConstructor;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.boot.context.properties.ConstructorBinding;

import java.util.ArrayList;
import java.util.List;

@Getter
@RequiredArgsConstructor
@ConstructorBinding
@ConfigurationProperties(prefix = "app")
public final class OAuth2Config {
	private final Auth auth;
	private final OAuth2 oAuth2;

	@Getter
	@RequiredArgsConstructor
	public static final class Auth {
		private final String tokenSecret;
		private final long accessTokenValidityInMs;
		private final long refreshTokenValidityInMs;
	}

	@Getter
	@RequiredArgsConstructor
	public static final class OAuth2 {
		private final List<String> authorizedRedirectUris = new ArrayList<>();
	}

}
