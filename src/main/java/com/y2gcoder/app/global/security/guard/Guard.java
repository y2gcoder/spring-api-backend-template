package com.y2gcoder.app.global.security.guard;

import com.y2gcoder.app.domain.member.constant.MemberRole;

import java.util.List;
import java.util.Set;
import java.util.stream.Collectors;

public abstract class Guard {
	public final boolean check(Long id) {
		return hasRole(getMemberRoles()) || isResourceOwner(id);
	}

	abstract protected List<MemberRole> getMemberRoles();

	abstract protected boolean isResourceOwner(Long id);

	private boolean hasRole(List<MemberRole> memberRoles) {
		Set<MemberRole> result = AuthHelper
				.extractMemberRoles()
				.stream()
				.filter(x -> memberRoles.stream().anyMatch(y -> x.getRole().equals(y.getRole())))
				.collect(Collectors.toSet());
		return !result.isEmpty();
	}

}
