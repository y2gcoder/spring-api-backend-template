package com.y2gcoder.app.global.config.security;

import lombok.Getter;
import lombok.RequiredArgsConstructor;
import org.hibernate.validator.constraints.URL;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.boot.context.properties.ConstructorBinding;
import org.springframework.validation.annotation.Validated;

import javax.validation.Valid;
import javax.validation.constraints.NotBlank;
import javax.validation.constraints.NotEmpty;
import javax.validation.constraints.Positive;
import java.util.List;

@Validated
@Getter
@RequiredArgsConstructor
@ConstructorBinding
@ConfigurationProperties(prefix = "app")
public final class OAuth2Config {
	@Valid
	private final Auth auth;
	@Valid
	private final OAuth2 oAuth2;

	@Getter
	@RequiredArgsConstructor
	public static final class Auth {
		@NotBlank
		private final String tokenSecret;
		@Positive
		private final long accessTokenValidityInMs;
		@Positive
		private final long refreshTokenValidityInMs;
	}

	@Getter
	@RequiredArgsConstructor
	public static final class OAuth2 {
		@NotEmpty
		private final List<@URL String> authorizedRedirectUris;
	}

}
