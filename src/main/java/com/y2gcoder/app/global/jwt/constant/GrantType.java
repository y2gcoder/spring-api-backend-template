package com.y2gcoder.app.global.jwt.constant;

import lombok.Getter;

@Getter
public enum GrantType {
	BEARER("Bearer");

	private final String type;

	GrantType(String type) {
		this.type = type;
	}
}
