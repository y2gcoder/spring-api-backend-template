package com.y2gcoder.app.api.auth.controller;

import com.y2gcoder.app.api.auth.service.AuthService;
import com.y2gcoder.app.api.auth.service.dto.SignInDto;
import com.y2gcoder.app.api.auth.service.dto.SignUpRequest;
import com.y2gcoder.app.api.auth.service.dto.TokenRefreshResponse;
import com.y2gcoder.app.global.jwt.dto.JwtTokenDto;
import com.y2gcoder.app.global.util.RefreshTokenCookieUtils;
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

	private final AuthService authService;
	private final RefreshTokenCookieUtils refreshTokenCookieUtils;

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
		String refreshTokenCookie = refreshTokenCookieUtils
				.generateRefreshTokenCookie(jwtTokenDto.getRefreshToken());

		return ResponseEntity.ok().header(HttpHeaders.SET_COOKIE, refreshTokenCookie).body(result);
	}

	@PostMapping("/refresh")
	public ResponseEntity<TokenRefreshResponse> refreshToken(@CookieValue("refreshtoken") String refreshToken) {

		JwtTokenDto jwtTokenDto = authService.refreshToken(refreshToken);

		String refreshTokenCookie = refreshTokenCookieUtils
				.generateRefreshTokenCookie(jwtTokenDto.getRefreshToken());

		TokenRefreshResponse response = TokenRefreshResponse.builder()
				.grantType(jwtTokenDto.getGrantType())
				.accessToken(jwtTokenDto.getAccessToken())
				.accessTokenExpireTime(jwtTokenDto.getAccessTokenExpireTime())
				.build();

		return ResponseEntity.ok().header(HttpHeaders.SET_COOKIE, refreshTokenCookie).body(response);
	}

	@PostMapping("/sign-out")
	public ResponseEntity<Void> signOut(@CookieValue("refreshtoken") String refreshToken) {

		authService.signOut(refreshToken);

		String signOutCookie = refreshTokenCookieUtils.generateSignOutCookie();

		return ResponseEntity.ok().header(HttpHeaders.SET_COOKIE, signOutCookie).build();
	}

}
