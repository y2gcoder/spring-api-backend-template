package com.y2gcoder.app.api.member.controller;

import com.y2gcoder.app.domain.member.service.MemberService;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RequiredArgsConstructor
@RequestMapping("/api/members")
@RestController
public class MemberController {

	private final MemberService memberService;

	@PreAuthorize("@memberGuard.check(#id)")
	@DeleteMapping("/{id}")
	public ResponseEntity<Void> withdrawMember(@PathVariable Long id) {
		memberService.withdrawMember(id);
		return ResponseEntity.ok().build();
	}

}
