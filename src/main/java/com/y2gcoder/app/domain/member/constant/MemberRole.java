package com.y2gcoder.app.domain.member.constant;

import lombok.Getter;
import lombok.RequiredArgsConstructor;

@Getter
@RequiredArgsConstructor
public enum MemberRole {
	ADMIN("ROLE_ADMIN", "admin"),
	USER("ROLE_USER", "user"),
	;

	private final String role;
	private final String name;
}
