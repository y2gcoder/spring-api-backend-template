package com.y2gcoder.app.global.resolver.signinmember;

import com.y2gcoder.app.domain.member.constant.MemberRole;
import lombok.Builder;
import lombok.Getter;

@Getter @Builder
public class SignInMemberDto {
	private Long memberId;
	private MemberRole role;
}
