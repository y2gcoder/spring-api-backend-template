package com.y2gcoder.app.api.member.controller;

import com.y2gcoder.app.api.member.service.MemberInfoService;
import com.y2gcoder.app.api.member.service.dto.MemberInfoDto;
import com.y2gcoder.app.global.config.security.guard.AuthHelper;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RequiredArgsConstructor
@RequestMapping("/api/members")
@RestController
public class MemberInfoController {

	private final MemberInfoService memberInfoService;

	@GetMapping("/me")
	public ResponseEntity<MemberInfoDto> whoAmI() {
		Long memberId = AuthHelper.extractMemberId();
		MemberInfoDto memberInfoDto = memberInfoService.getMemberInfo(memberId);
		return ResponseEntity.ok(memberInfoDto);
	}

}
