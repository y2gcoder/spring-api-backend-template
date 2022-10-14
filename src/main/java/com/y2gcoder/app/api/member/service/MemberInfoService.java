package com.y2gcoder.app.api.member.service;

import com.y2gcoder.app.api.member.service.dto.MemberInfoDto;
import com.y2gcoder.app.domain.member.entity.Member;
import com.y2gcoder.app.domain.member.service.MemberService;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;

@RequiredArgsConstructor
@Service
public class MemberInfoService {
	private final MemberService memberService;

	public MemberInfoDto getMemberInfo(Long memberId) {
		Member member = memberService.findMemberById(memberId);
		return MemberInfoDto.builder()
				.memberId(member.getId())
				.email(member.getEmail())
				.nickname(member.getNickname())
				.profile(member.getProfile())
				.role(member.getRole().getName())
				.build();
	}
}
