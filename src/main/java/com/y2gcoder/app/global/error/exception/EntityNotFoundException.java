package com.y2gcoder.app.global.error.exception;

import com.y2gcoder.app.global.error.ErrorCode;

public class EntityNotFoundException extends BusinessException {
	public EntityNotFoundException(ErrorCode errorCode) {
		super(errorCode);
	}
}
