package com.y2gcoder.app.domain.member.service;

import com.y2gcoder.app.domain.member.entity.Member;
import com.y2gcoder.app.domain.member.repository.MemberRepository;
import com.y2gcoder.app.global.error.ErrorCode;
import com.y2gcoder.app.global.error.exception.EntityNotFoundException;
import com.y2gcoder.app.global.util.DateTimeUtils;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.Date;

@RequiredArgsConstructor
@Transactional(readOnly = true)
@Service
public class MemberService {
	private final MemberRepository memberRepository;


	@Transactional
	public void updateRefreshToken(Long memberId, String refreshToken, Date refreshTokenExpireTime) {
		Member member = memberRepository
				.findById(memberId)
				.orElseThrow(() -> new EntityNotFoundException(ErrorCode.NOT_FOUND_MEMBER));
		member.updateRefreshToken(refreshToken, DateTimeUtils.convertToLocalDateTime(refreshTokenExpireTime));
	}
}
