package com.y2gcoder.app.domain.member.constant;

import lombok.Getter;
import lombok.RequiredArgsConstructor;

import java.util.Arrays;

@Getter
@RequiredArgsConstructor
public enum MemberRole {
	ADMIN("ROLE_ADMIN", "admin"),
	USER("ROLE_USER", "user"),
	;

	private final String role;
	private final String name;

	public static MemberRole from(String authorityString) {
		return Arrays.stream(MemberRole.values())
				.filter(role -> role.getRole().equals(authorityString)).findAny().orElse(null);
	}
}
