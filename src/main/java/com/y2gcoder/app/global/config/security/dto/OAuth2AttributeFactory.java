package com.y2gcoder.app.global.config.security.dto;

import com.y2gcoder.app.domain.member.constant.AuthProvider;
import com.y2gcoder.app.global.error.ErrorCode;
import com.y2gcoder.app.global.error.exception.AuthenticationException;

import java.util.Map;

public class OAuth2AttributeFactory {
	public static OAuth2Attributes getOAuth2Attributes(String registrationId, Map<String, Object> attributes) {
		if (registrationId.equalsIgnoreCase(AuthProvider.google.toString())) {
			return new GoogleOAuthAttributes(attributes);
		} else {
			throw new AuthenticationException(ErrorCode.NOT_EXISTS_AUTH_PROVIDER);
		}
	}
}
