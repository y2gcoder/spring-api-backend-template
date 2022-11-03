package com.y2gcoder.app.api.auth.controller;

import com.y2gcoder.app.api.auth.service.AuthService;
import com.y2gcoder.app.api.auth.service.dto.SignInDto;
import com.y2gcoder.app.api.auth.service.dto.SignUpRequest;
import com.y2gcoder.app.api.auth.service.dto.TokenRefreshDto;
import com.y2gcoder.app.global.jwt.dto.JwtTokenDto;
import com.y2gcoder.app.global.resolver.signinmember.SignInMember;
import com.y2gcoder.app.global.resolver.signinmember.SignInMemberDto;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import javax.validation.Valid;

@RequiredArgsConstructor
@RequestMapping("/api/auth/")
@RestController
public class AuthController {

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
				.refreshToken(jwtTokenDto.getRefreshToken())
				.refreshTokenExpireTime(jwtTokenDto.getRefreshTokenExpireTime())
				.build();
		return ResponseEntity.ok().body(result);
	}

	@PostMapping("/refresh")
	public ResponseEntity<TokenRefreshDto.Response> refreshToken(@Valid @RequestBody TokenRefreshDto.Request request) {
		return ResponseEntity.ok(authService.refreshToken(request));
	}

	@PostMapping("/sign-out")
	public ResponseEntity<Void> signOut(@SignInMember SignInMemberDto signInMemberDto) {
		authService.signOut(signInMemberDto.getMemberId());
		return ResponseEntity.ok().build();
	}

}
