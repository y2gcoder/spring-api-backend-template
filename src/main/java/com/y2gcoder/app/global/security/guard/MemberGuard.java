package com.y2gcoder.app.global.security.guard;

import com.y2gcoder.app.domain.member.constant.MemberRole;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Component;

import java.util.List;

@RequiredArgsConstructor
@Component
public class MemberGuard extends Guard {
	private final List<MemberRole> memberRoles = List.of(MemberRole.ADMIN);
	@Override
	protected List<MemberRole> getMemberRoles() {
		return memberRoles;
	}

	@Override
	protected boolean isResourceOwner(Long id) {
		return id.equals(AuthHelper.extractMemberId());
	}
}
