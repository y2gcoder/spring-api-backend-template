package com.y2gcoder.app.global.error;

import lombok.AccessLevel;
import lombok.Builder;
import lombok.Getter;
import lombok.NoArgsConstructor;
import org.springframework.validation.BindingResult;
import org.springframework.validation.FieldError;

import java.util.List;

@Getter
@NoArgsConstructor(access = AccessLevel.PRIVATE)
public class ErrorResponse {
	private String errorCode;
	private String errorMessage;

	@Builder
	public ErrorResponse(String errorCode, String errorMessage) {
		this.errorCode = errorCode;
		this.errorMessage = errorMessage;
	}

	public static ErrorResponse of(String errorCode, String errorMessage) {
		return ErrorResponse.builder()
				.errorCode(errorCode)
				.errorMessage(errorMessage)
				.build();
	}

	public static ErrorResponse of(String errorCode, BindingResult bindingResult) {
		return ErrorResponse.builder()
				.errorCode(errorCode)
				.errorMessage(createErrorMessage(bindingResult))
				.build();
	}

	private static String createErrorMessage(BindingResult bindingResult) {
		StringBuilder sb = new StringBuilder();
		boolean isFirst = true;
		List<FieldError> fieldErrors = bindingResult.getFieldErrors();
		for (FieldError fieldError : fieldErrors) {
			if(!isFirst) {
				sb.append(", ");
			} else {
				isFirst = false;
			}
			sb.append("[");
			sb.append(fieldError.getField());
			sb.append("]");
			sb.append(fieldError.getDefaultMessage());
		}

		return sb.toString();
	}
}
