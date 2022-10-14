package com.y2gcoder.app.domain.member.service;

import com.y2gcoder.app.domain.member.entity.Member;
import com.y2gcoder.app.domain.member.repository.MemberRepository;
import com.y2gcoder.app.global.error.ErrorCode;
import com.y2gcoder.app.global.error.exception.AuthenticationException;
import com.y2gcoder.app.global.error.exception.EntityNotFoundException;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.LocalDateTime;

@RequiredArgsConstructor
@Transactional(readOnly = true)
@Service
public class MemberService {
	private final MemberRepository memberRepository;

	@Transactional
	public void updateRefreshToken(Long memberId, String refreshToken, LocalDateTime refreshTokenExpireTime) {
		Member member = memberRepository
				.findById(memberId)
				.orElseThrow(() -> new EntityNotFoundException(ErrorCode.NOT_FOUND_MEMBER));
		member.updateRefreshToken(refreshToken, refreshTokenExpireTime);
	}

	public Member findMemberByRefreshToken(String refreshToken) {
		Member member = memberRepository
				.findByRefreshToken(refreshToken)
				.orElseThrow(() -> new AuthenticationException(ErrorCode.NOT_FOUND_REFRESH_TOKEN));
		LocalDateTime tokenExpirationTime = member.getTokenExpirationTime();
		if (tokenExpirationTime.isBefore(LocalDateTime.now())) {
			throw new AuthenticationException(ErrorCode.EXPIRED_REFRESH_TOKEN);
		}

		return member;
	}

	public Member findMemberById(Long memberId) {
		return memberRepository
				.findById(memberId)
				.orElseThrow(() -> new EntityNotFoundException(ErrorCode.NOT_FOUND_MEMBER));
	}
}
