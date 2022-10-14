package com.y2gcoder.app.api.member.service.dto;

import lombok.Builder;
import lombok.Getter;

@Getter @Builder
public class MemberInfoDto {
	private Long memberId;
	private String email;
	private String nickname;
	private String profile;
	private String role;
}
