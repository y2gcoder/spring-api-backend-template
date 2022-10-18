package com.y2gcoder.app.global.jwt.constant;

import lombok.Getter;

@Getter
public enum ClaimKeyType {
	MEMBER_ID("memberId"),
	ROLE("role"),
	;

	private final String type;

	ClaimKeyType(String type) {
		this.type = type;
	}
}
