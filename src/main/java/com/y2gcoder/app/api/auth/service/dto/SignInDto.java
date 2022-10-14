package com.y2gcoder.app.api.auth.service.dto;


import com.fasterxml.jackson.annotation.JsonFormat;
import lombok.Builder;
import lombok.Getter;
import lombok.Setter;

import javax.validation.constraints.Email;
import javax.validation.constraints.NotBlank;
import java.time.LocalDateTime;

public class SignInDto {

	@Getter
	@Setter
	public static class Request {

		@NotBlank(message = "이메일을 입력해주세요.")
		@Email(message = "올바른 이메일 형식이 아닙니다.")
		private String email;

		@NotBlank(message = "비밀번호를 입력해주세요.")
		private String password;
	}

	@Getter @Builder
	public static class Response {

		private String grantType;

		private String accessToken;

		@JsonFormat(shape = JsonFormat.Shape.STRING, pattern = "yyyy-MM-dd HH:mm:ss", timezone = "Asia/Seoul")
		private LocalDateTime accessTokenExpireTime;
	}
}
