package com.y2gcoder.app.global.config.security.dto;

import lombok.ToString;

import java.util.Map;

@ToString
public abstract class OAuth2Attributes {
	protected Map<String, Object> attributes;

	public OAuth2Attributes(Map<String, Object> attributes) {
		this.attributes = attributes;
	}

	public Map<String, Object> getAttributes() {
		return attributes;
	}

	public abstract String getProvider();

	public abstract String getId();

	public abstract String getName();

	public abstract String getEmail();

	public abstract String getImageUrl();
}
