package com.y2gcoder.app.global.error;

import lombok.Getter;
import org.springframework.http.HttpStatus;

@Getter
public enum ErrorCode {
	//OAuth2
	NOT_EXISTS_AUTH_PROVIDER(HttpStatus.UNAUTHORIZED, "OA-001", "해당 OAuth2 Provider는 지원하지 않습니다."),
	INVALID_AUTH_PROVIDER(HttpStatus.UNAUTHORIZED, "OA-002", "해당 OAuth2 Provider로 로그인한 회원이 아닙니다."),
	IS_NOT_REDIRECT_URI(HttpStatus.BAD_REQUEST, "OA-003", "리다이렉트 URI가 일치하지 않습니다."),

	//인증 && 인가
	NOT_FOUND_REFRESH_TOKEN(HttpStatus.UNAUTHORIZED, "A-001", "해당 refresh token은 존재하지 않습니다."),
	EXPIRED_REFRESH_TOKEN(HttpStatus.UNAUTHORIZED, "A-002", "해당 refresh token은 만료되었습니다."),
	INVALID_REFRESH_TOKEN(HttpStatus.UNAUTHORIZED, "A-003", "유효하지 않은 refresh token입니다."),
	MISMATCH_PASSWORD(HttpStatus.BAD_REQUEST, "A-004", "비밀번호가 일치하지 않습니다."),

	//회원
	NOT_FOUND_MEMBER(HttpStatus.BAD_REQUEST, "M-001", "해당 회원을 찾을 수 없습니다."),
	ALREADY_REGISTERED_MEMBER(HttpStatus.BAD_REQUEST, "M-002", "이미 가입된 회원입니다."),
	;
	private final HttpStatus httpStatus;
	private final String errorCode;
	private final String message;

	ErrorCode(HttpStatus httpStatus, String errorCode, String message) {
		this.httpStatus = httpStatus;
		this.errorCode = errorCode;
		this.message = message;
	}
}
