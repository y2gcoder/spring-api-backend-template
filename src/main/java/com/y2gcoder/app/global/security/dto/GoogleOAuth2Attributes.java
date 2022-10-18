package com.y2gcoder.app.global.security.dto;

import com.y2gcoder.app.domain.member.constant.AuthProvider;

import java.util.Map;

public class GoogleOAuth2Attributes extends OAuth2Attributes {

	public GoogleOAuth2Attributes(Map<String, Object> attributes) {
		super(attributes);
	}

	@Override
	public String getProvider() {
		return AuthProvider.google.toString();
	}

	@Override
	public String getId() {
		return (String) attributes.get("sub");
	}

	@Override
	public String getName() {
		return (String) attributes.get("name");
	}

	@Override
	public String getEmail() {
		return (String) attributes.get("email");
	}

	@Override
	public String getImageUrl() {
		return (String) attributes.get("picture");
	}
}
