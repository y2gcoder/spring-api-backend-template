package com.y2gcoder.app.api.auth.service;

import com.y2gcoder.app.domain.member.entity.Member;
import com.y2gcoder.app.domain.member.service.MemberService;
import com.y2gcoder.app.global.config.jwt.dto.JwtTokenDto;
import com.y2gcoder.app.global.config.jwt.service.JwtTokenProvider;
import com.y2gcoder.app.global.config.security.OAuth2Config;
import com.y2gcoder.app.global.error.ErrorCode;
import com.y2gcoder.app.global.error.exception.AuthenticationException;
import com.y2gcoder.app.global.util.CookieUtils;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

@RequiredArgsConstructor
@Transactional(readOnly = true)
@Service
public class AuthService {
	private final OAuth2Config oAuth2Config;
	private final JwtTokenProvider jwtTokenProvider;
	private final MemberService memberService;

	@Transactional
	public JwtTokenDto refreshToken(HttpServletRequest request, HttpServletResponse response) {
		String refreshToken = CookieUtils.getCookie(request, oAuth2Config.getAuth().getRefreshCookieKey())
				.map(Cookie::getValue).orElseThrow(() -> new AuthenticationException(ErrorCode.NOT_FOUND_REFRESH_TOKEN));
		validateRefreshToken(refreshToken);
		Member member = memberService.findMemberByRefreshToken(refreshToken);
		JwtTokenDto jwtTokenDto = jwtTokenProvider.createJwtToken(String.valueOf(member.getId()), member.getRole());
		memberService.updateRefreshToken(
				member.getId(),
				jwtTokenDto.getRefreshToken(),
				jwtTokenDto.getRefreshTokenExpireTime()
		);

		CookieUtils.addRefreshTokenCookie(
				response,
				oAuth2Config.getAuth().getRefreshCookieKey(),
				jwtTokenDto.getRefreshToken(),
				oAuth2Config.getAuth().getRefreshTokenValidityInMs()
		);

		return jwtTokenDto;
	}

	private void validateRefreshToken(String refreshToken) {
		boolean validateToken = jwtTokenProvider.validateToken(refreshToken);
		if (!validateToken) {
			throw new AuthenticationException(ErrorCode.INVALID_REFRESH_TOKEN);
		}
	}
}
