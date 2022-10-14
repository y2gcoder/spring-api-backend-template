package com.y2gcoder.app.api.auth.controller;

import com.y2gcoder.app.api.auth.service.AuthService;
import com.y2gcoder.app.api.auth.service.dto.SignInDto;
import com.y2gcoder.app.api.auth.service.dto.SignUpRequest;
import com.y2gcoder.app.global.config.jwt.dto.JwtTokenDto;
import com.y2gcoder.app.global.config.security.OAuth2Config;
import com.y2gcoder.app.global.util.CookieUtils;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import javax.validation.Valid;

@RequiredArgsConstructor
@RequestMapping("/api/auth/")
@RestController
public class AuthController {
	private final OAuth2Config oAuth2Config;
	private final AuthService authService;

	@PostMapping("/sign-up")
	public ResponseEntity<Void> signUp(@Valid @RequestBody SignUpRequest request) {
		authService.signUp(request);
		return ResponseEntity.status(HttpStatus.CREATED).build();
	}

	@PostMapping("/sign-in")
	public ResponseEntity<SignInDto.Response> signIn(@Valid @RequestBody SignInDto.Request req) {
		JwtTokenDto jwtTokenDto = authService.signIn(req);
		SignInDto.Response result = SignInDto.Response.builder()
				.grantType(jwtTokenDto.getGrantType())
				.accessToken(jwtTokenDto.getAccessToken())
				.accessTokenExpireTime(jwtTokenDto.getAccessTokenExpireTime())
				.build();

		//Cookie에 refresh token 저장!!
		String generatedRefreshTokenCookie = generateRefreshTokenCookie(jwtTokenDto.getRefreshToken());

		return ResponseEntity.ok().header(HttpHeaders.SET_COOKIE, generatedRefreshTokenCookie).body(result);
	}

	@PostMapping("/refresh")
	public ResponseEntity<JwtTokenDto> refreshToken(@CookieValue("refreshtoken") String refreshToken) {

		JwtTokenDto jwtTokenDto = authService.refreshToken(refreshToken);

		String generatedRefreshTokenCookie = generateRefreshTokenCookie(jwtTokenDto.getRefreshToken());

		return ResponseEntity.ok().header(HttpHeaders.SET_COOKIE, generatedRefreshTokenCookie).body(jwtTokenDto);
	}

	private String generateRefreshTokenCookie(String refreshToken) {
		return CookieUtils.generateResponseCookie(
				oAuth2Config.getAuth().getRefreshCookieKey(),
				refreshToken,
				oAuth2Config.getAuth().getRefreshTokenValidityInMs() / 1000
		).toString();
	}

	@PostMapping("/sign-out")
	public ResponseEntity<Void> signOut(@CookieValue("refreshtoken") String refreshToken) {

		authService.signOut(refreshToken);

		String generatedSignOutCookie = generateSignOutCookie();

		return ResponseEntity.ok().header(HttpHeaders.SET_COOKIE, generatedSignOutCookie).build();
	}

	private String generateSignOutCookie() {
		return CookieUtils.generateResponseCookie(
				oAuth2Config.getAuth().getRefreshCookieKey(),
				"",
				1
		).toString();
	}

}
