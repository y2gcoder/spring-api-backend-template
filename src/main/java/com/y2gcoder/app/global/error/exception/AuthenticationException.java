package com.y2gcoder.app.global.error.exception;

import com.y2gcoder.app.global.error.ErrorCode;

public class AuthenticationException extends BusinessException {
	public AuthenticationException(ErrorCode errorCode) {
		super(errorCode);
	}
}
