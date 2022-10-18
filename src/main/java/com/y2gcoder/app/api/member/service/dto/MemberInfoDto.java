package com.y2gcoder.app.api.member.service.dto;

import lombok.Builder;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

@Getter
@Setter
@NoArgsConstructor
public class MemberInfoDto {
	private Long memberId;
	private String email;
	private String nickname;
	private String profile;
	private String role;

	@Builder
	public MemberInfoDto(Long memberId, String email, String nickname, String profile, String role) {
		this.memberId = memberId;
		this.email = email;
		this.nickname = nickname;
		this.profile = profile;
		this.role = role;
	}
}
