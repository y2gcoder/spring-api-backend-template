package com.y2gcoder.app.api.auth.controller;

import com.y2gcoder.app.api.auth.service.AuthService;
import com.y2gcoder.app.global.config.jwt.dto.JwtTokenDto;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

@RequiredArgsConstructor
@RequestMapping("/api/auth/")
@RestController
public class AuthController {

	private final AuthService authService;

	@PostMapping("/refresh")
	public ResponseEntity<JwtTokenDto> refreshToken(HttpServletRequest request, HttpServletResponse response) {
		return ResponseEntity.ok(authService.refreshToken(request, response));
	}
}
