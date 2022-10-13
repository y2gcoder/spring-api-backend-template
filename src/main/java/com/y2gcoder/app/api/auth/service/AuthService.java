package com.y2gcoder.app.api.auth.service;

import com.y2gcoder.app.domain.member.entity.Member;
import com.y2gcoder.app.domain.member.service.MemberService;
import com.y2gcoder.app.global.config.jwt.dto.JwtTokenDto;
import com.y2gcoder.app.global.config.jwt.service.JwtTokenProvider;
import com.y2gcoder.app.global.error.ErrorCode;
import com.y2gcoder.app.global.error.exception.AuthenticationException;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.LocalDateTime;

@RequiredArgsConstructor
@Transactional(readOnly = true)
@Service
public class AuthService {
	private final JwtTokenProvider jwtTokenProvider;
	private final MemberService memberService;

	@Transactional
	public JwtTokenDto refreshToken(String refreshToken) {

		validateRefreshToken(refreshToken);
		Member member = memberService.findMemberByRefreshToken(refreshToken);

		JwtTokenDto jwtTokenDto = jwtTokenProvider.createJwtToken(String.valueOf(member.getId()), member.getRole());

		member.updateRefreshToken(jwtTokenDto.getRefreshToken(), jwtTokenDto.getRefreshTokenExpireTime());

		return jwtTokenDto;
	}

	@Transactional
	public void signOut(String refreshToken) {

		validateRefreshToken(refreshToken);
		Member member = memberService.findMemberByRefreshToken(refreshToken);

		member.updateRefreshToken("", LocalDateTime.now());
	}

	private void validateRefreshToken(String refreshToken) {
		boolean validateToken = jwtTokenProvider.validateToken(refreshToken);
		if (!validateToken) {
			throw new AuthenticationException(ErrorCode.INVALID_REFRESH_TOKEN);
		}
	}
}
