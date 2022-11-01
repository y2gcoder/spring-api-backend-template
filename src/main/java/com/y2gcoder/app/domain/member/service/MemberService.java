package com.y2gcoder.app.domain.member.service;

import com.y2gcoder.app.domain.member.entity.Member;
import com.y2gcoder.app.domain.member.repository.MemberRepository;
import com.y2gcoder.app.global.error.ErrorCode;
import com.y2gcoder.app.global.error.exception.EntityNotFoundException;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@RequiredArgsConstructor
@Transactional(readOnly = true)
@Service
public class MemberService {
	private final MemberRepository memberRepository;

	@Transactional
	public void registerMember(Member member) {
		memberRepository.save(member);
	}

	public Member findMemberById(Long memberId) {
		return memberRepository
				.findById(memberId)
				.orElseThrow(() -> new EntityNotFoundException(ErrorCode.NOT_FOUND_MEMBER));
	}

	public boolean existsMemberByEmail(String email) {
		return memberRepository.existsByEmail(email);
	}

	public Member findMemberByEmail(String email) {
		return memberRepository
				.findByEmail(email)
				.orElseThrow(() -> new EntityNotFoundException(ErrorCode.NOT_FOUND_MEMBER));
	}

	@Transactional
	public void withdrawMember(Long memberId) {
		Member member = memberRepository
				.findById(memberId)
				.orElseThrow(() -> new EntityNotFoundException(ErrorCode.NOT_FOUND_MEMBER));
		memberRepository.delete(member);
	}
}
