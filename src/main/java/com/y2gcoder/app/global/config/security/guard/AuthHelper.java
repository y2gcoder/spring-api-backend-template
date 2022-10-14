package com.y2gcoder.app.global.config.security.guard;

import com.y2gcoder.app.domain.member.constant.MemberRole;
import com.y2gcoder.app.global.config.security.dto.CustomUserDetails;
import lombok.AccessLevel;
import lombok.NoArgsConstructor;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;

import java.util.Set;
import java.util.stream.Collectors;

@NoArgsConstructor(access = AccessLevel.PRIVATE)
public class AuthHelper {

	public static Long extractMemberId() {
		return getUserDetails().getId();
	}

	public static Set<MemberRole> extractMemberRoles() {
		return getUserDetails().getAuthorities()
				.stream()
				.map(GrantedAuthority::getAuthority)
				.map(MemberRole::from)
				.collect(Collectors.toSet());
	}

	private static CustomUserDetails getUserDetails() {
		return (CustomUserDetails) getAuthentication().getPrincipal();
	}

	private static Authentication getAuthentication() {
		return SecurityContextHolder.getContext().getAuthentication();
	}
}
