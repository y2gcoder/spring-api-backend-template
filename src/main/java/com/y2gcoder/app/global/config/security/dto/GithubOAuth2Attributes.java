package com.y2gcoder.app.global.config.security.dto;

import com.y2gcoder.app.domain.member.constant.AuthProvider;
import org.springframework.util.StringUtils;

import java.util.Map;

public class GithubOAuth2Attributes extends OAuth2Attributes {

	public GithubOAuth2Attributes(Map<String, Object> attributes) {
		super(attributes);
	}

	@Override
	public String getProvider() {
		return AuthProvider.github.toString();
	}

	@Override
	public String getId() {
		return ((Integer) attributes.get("id")).toString();
	}

	@Override
	public String getName() {
		return (String) attributes.get("name");
	}

	@Override
	public String getEmail() {
		return
				attributes.get("email") != null && StringUtils.hasText(attributes.get("email").toString())
						? attributes.get("email").toString()
						: ((Integer) attributes.get("login")).toString();
	}

	@Override
	public String getImageUrl() {
		return (String) attributes.get("avatar_url");
	}
}
