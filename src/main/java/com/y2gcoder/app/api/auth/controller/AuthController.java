package com.y2gcoder.app.api.auth.controller;

import com.y2gcoder.app.api.auth.service.AuthService;
import com.y2gcoder.app.global.config.jwt.dto.JwtTokenDto;
import com.y2gcoder.app.global.config.security.OAuth2Config;
import com.y2gcoder.app.global.error.ErrorCode;
import com.y2gcoder.app.global.error.exception.AuthenticationException;
import com.y2gcoder.app.global.util.CookieUtils;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

@RequiredArgsConstructor
@RequestMapping("/api/auth/")
@RestController
public class AuthController {
	private final OAuth2Config oAuth2Config;
	private final AuthService authService;

	@PostMapping("/refresh")
	public ResponseEntity<JwtTokenDto> refreshToken(HttpServletRequest request, HttpServletResponse response) {
		String refreshToken = CookieUtils.getCookie(request, oAuth2Config.getAuth().getRefreshCookieKey())
				.map(Cookie::getValue).orElseThrow(() -> new AuthenticationException(ErrorCode.NOT_FOUND_REFRESH_TOKEN));

		JwtTokenDto jwtTokenDto = authService.refreshToken(refreshToken);

		CookieUtils.addRefreshTokenCookie(
				response,
				oAuth2Config.getAuth().getRefreshCookieKey(),
				jwtTokenDto.getRefreshToken(),
				oAuth2Config.getAuth().getRefreshTokenValidityInMs()
		);

		return ResponseEntity.ok(jwtTokenDto);
	}
	@PostMapping("/sign-out")
	public ResponseEntity<Void> signOut(HttpServletRequest request, HttpServletResponse response) {
		String refreshToken = CookieUtils.getCookie(request, oAuth2Config.getAuth().getRefreshCookieKey())
				.map(Cookie::getValue).orElseThrow(() -> new AuthenticationException(ErrorCode.NOT_FOUND_REFRESH_TOKEN));

		authService.signOut(refreshToken);

		CookieUtils.deleteCookie(request, response, oAuth2Config.getAuth().getRefreshCookieKey());

		return ResponseEntity.ok().build();
	}
}
